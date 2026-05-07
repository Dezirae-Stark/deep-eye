"""Tests for the bridge enrichment phase (Task 18).

This module is the policy layer that sits between deep_eye.py's CLI and
the ShadowbrokerClient. It enforces the operator's chosen failure modes
(all 'hard exit') by raising BridgeStartError, which deep_eye.py turns
into a non-zero exit + clear message.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import pytest


@dataclass
class FakeArgs:
    """Stand-in for argparse.Namespace, just the bridge-relevant flags."""
    no_bridge: bool = False
    bridge_scope_token: Optional[str] = None
    bridge_base_url: Optional[str] = None


def _config(**overrides) -> dict:
    """Minimal config with shadowbroker_bridge configured. Test override
    individual keys via kwargs.

    Note: scope_manifest_path is intentionally NOT set here — tests that
    exercise the local-scope-enforcer path (Codex R2 P2) set it explicitly
    pointing at a tmp_path manifest. Bridge-behavior tests get bridge-only
    enforcement, which is what they're verifying.
    """
    base = {
        "shadowbroker_bridge": {
            "enabled": True,
            "base_url": "http://bridge.test",
            "key_id": "test-key",
            "scope_token": "engagement-test",
            "timeout": 5.0,
        }
    }
    base["shadowbroker_bridge"].update(overrides)
    return base


class TestRunBridgePhase:
    def test_bridge_disabled_in_config_returns_none(self, monkeypatch):
        from core.bridge_enrichment import run_bridge_phase

        result = run_bridge_phase(_config(enabled=False), "https://acme.com", FakeArgs())
        assert result is None

    def test_no_bridge_cli_flag_overrides_enabled(self, monkeypatch):
        from core.bridge_enrichment import run_bridge_phase

        # Even though config has enabled=True, --no-bridge wins.
        result = run_bridge_phase(_config(), "https://acme.com", FakeArgs(no_bridge=True))
        assert result is None

    def test_missing_env_key_raises_start_error(self, monkeypatch):
        from core.bridge_enrichment import BridgeStartError, run_bridge_phase

        monkeypatch.delenv("BRIDGE_HMAC_KEY", raising=False)
        with pytest.raises(BridgeStartError, match="BRIDGE_HMAC_KEY"):
            run_bridge_phase(_config(), "https://acme.com", FakeArgs())

    def test_invalid_hex_in_env_raises_start_error(self, monkeypatch):
        from core.bridge_enrichment import BridgeStartError, run_bridge_phase

        monkeypatch.setenv("BRIDGE_HMAC_KEY", "not-hex-zzz")
        with pytest.raises(BridgeStartError, match="hex"):
            run_bridge_phase(_config(), "https://acme.com", FakeArgs())

    # Codex R3 P1: the previous "reject before bridge" behavior turned the
    # local manifest into a hard gate. A stale local copy could block scans
    # the bridge would legitimately allow. The local check is now ADVISORY:
    # we always consult the bridge; the local result only drives logging.

    def _local_scope_yaml(self, tmp_path, *, allowed_domain="acme.com",
                          manifest_id="local-test"):
        """Helper: write a minimal local manifest authorizing allowed_domain."""
        from datetime import datetime, timezone, timedelta
        import yaml
        scope_path = tmp_path / "manifest.yml"
        scope_path.write_text(yaml.safe_dump({
            "version": 1,
            "manifest_id": manifest_id,
            "mode": "engagement",
            "created_at": "2025-01-01T00:00:00Z",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            "authorization": {"contract_ref": "x", "contact": "y@z"},
            "targets": {"include": {"domains": [allowed_domain]}},
        }))
        return scope_path

    def test_local_scope_no_does_not_block_when_bridge_says_yes(
            self, monkeypatch, tmp_path, caplog):
        """Codex R3 P1: a stale local manifest must NOT block scans the
        bridge would allow. Local says no, bridge says yes → proceed.
        Operators still see a warning that their local copy is stale."""
        import logging
        from core.bridge_enrichment import run_bridge_phase
        from core.scope_manifest import ScopeResult

        # Local manifest only allows acme.com — the bridge knows about other.test.
        scope_path = self._local_scope_yaml(tmp_path, allowed_domain="acme.com")
        monkeypatch.setenv("BRIDGE_HMAC_KEY", "ab" * 16)

        class FakeClient:
            def scope_check(self, target, scope_token):
                return ScopeResult(in_scope=True, reason="bridge allows",
                                   manifest_id="bridge-m", mode="engagement")
            def enrich(self, target):
                return {"target": target, "feed_errors": {}}
            def close(self):
                pass

        monkeypatch.setattr("core.bridge_enrichment._build_client",
                            lambda *a, **kw: FakeClient())

        cfg = _config()
        cfg["shadowbroker_bridge"]["scope_manifest_path"] = str(scope_path)

        with caplog.at_level(logging.WARNING, logger="core.bridge_enrichment"):
            result = run_bridge_phase(cfg, "https://other.test", FakeArgs())

        assert result is not None, "bridge said yes — scan must proceed"
        # Operator gets a stale-local warning so they know to refresh.
        assert any(
            "stale" in r.message.lower() or "refresh" in r.message.lower()
            for r in caplog.records
        ), (
            "expected stale-local-manifest warning when local-no/bridge-yes; "
            f"got: {[r.message for r in caplog.records]}"
        )

    def test_local_scope_no_with_bridge_no_still_raises_start_error(
            self, monkeypatch, tmp_path):
        """Local-no AND bridge-no: still raise. The bridge is the authority,
        and it agrees the target is out of scope. Reason should come from
        the bridge, not the local cache."""
        from core.bridge_enrichment import BridgeStartError, run_bridge_phase
        from core.scope_manifest import ScopeResult

        scope_path = self._local_scope_yaml(tmp_path, allowed_domain="acme.com")
        monkeypatch.setenv("BRIDGE_HMAC_KEY", "ab" * 16)

        class FakeClient:
            def scope_check(self, target, scope_token):
                return ScopeResult(in_scope=False, reason="bridge denies too",
                                   manifest_id="bridge-m", mode="engagement")
            def close(self):
                pass

        monkeypatch.setattr("core.bridge_enrichment._build_client",
                            lambda *a, **kw: FakeClient())

        cfg = _config()
        cfg["shadowbroker_bridge"]["scope_manifest_path"] = str(scope_path)

        with pytest.raises(BridgeStartError, match="bridge denies too"):
            run_bridge_phase(cfg, "https://elsewhere.test", FakeArgs())

    def test_local_scope_manifest_drift_warning_when_local_yes_remote_no(self, monkeypatch, tmp_path, caplog):
        """When local manifest says yes but the bridge says no, we still
        fail closed (the bridge is authoritative) but log a drift warning
        so operators know the local copy is out of date."""
        from core.bridge_enrichment import BridgeStartError, run_bridge_phase
        from core.scope_manifest import ScopeResult
        from datetime import datetime, timezone, timedelta
        import logging
        import yaml

        scope_path = tmp_path / "manifest.yml"
        scope_path.write_text(yaml.safe_dump({
            "version": 1,
            "manifest_id": "local-stale",
            "mode": "engagement",
            "created_at": "2025-01-01T00:00:00Z",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            "authorization": {"contract_ref": "x", "contact": "y@z"},
            "targets": {"include": {"domains": ["acme.com"]}},
        }))

        monkeypatch.setenv("BRIDGE_HMAC_KEY", "ab" * 16)

        class FakeClient:
            def scope_check(self, target, scope_token):
                return ScopeResult(in_scope=False, reason="bridge says no",
                                   manifest_id="m", mode="engagement")
            def close(self):
                pass

        monkeypatch.setattr("core.bridge_enrichment._build_client",
                            lambda *a, **kw: FakeClient())

        cfg = _config()
        cfg["shadowbroker_bridge"]["scope_manifest_path"] = str(scope_path)
        with caplog.at_level(logging.WARNING, logger="core.bridge_enrichment"):
            with pytest.raises(BridgeStartError):
                run_bridge_phase(cfg, "https://acme.com", FakeArgs())
        assert any("drift" in r.message.lower() for r in caplog.records), (
            "expected a drift warning when local-yes/remote-no"
        )

    def test_missing_local_manifest_path_logged_but_continues(self, monkeypatch, tmp_path):
        """If scope_manifest_path is set but the file doesn't exist, log a
        warning and proceed with bridge-only enforcement. Don't crash —
        defense-in-depth is opportunistic, the bridge is authoritative."""
        from core.bridge_enrichment import run_bridge_phase
        from core.scope_manifest import ScopeResult

        monkeypatch.setenv("BRIDGE_HMAC_KEY", "ab" * 16)

        class FakeClient:
            def scope_check(self, *a, **kw):
                return ScopeResult(in_scope=True, reason="ok", manifest_id="m", mode="engagement")
            def enrich(self, *a, **kw):
                return {"target": "acme.com"}
            def close(self):
                pass

        monkeypatch.setattr("core.bridge_enrichment._build_client",
                            lambda *a, **kw: FakeClient())

        cfg = _config()
        cfg["shadowbroker_bridge"]["scope_manifest_path"] = str(tmp_path / "missing.yml")
        result = run_bridge_phase(cfg, "https://acme.com", FakeArgs())
        # Bridge said yes, local was unavailable — we still got intel.
        assert result is not None

    @pytest.mark.parametrize("missing_key", ["base_url", "key_id", "scope_token"])
    def test_missing_required_config_key_raises_start_error(self, monkeypatch, missing_key):
        """Codex P2: missing config keys must raise BridgeStartError with a
        clear message identifying the key — not a bare KeyError that bypasses
        our fail-closed error handling and looks like a generic crash to the
        operator."""
        from core.bridge_enrichment import BridgeStartError, run_bridge_phase

        monkeypatch.setenv("BRIDGE_HMAC_KEY", "ab" * 16)
        cfg = _config()
        del cfg["shadowbroker_bridge"][missing_key]
        with pytest.raises(BridgeStartError, match=missing_key):
            run_bridge_phase(cfg, "https://acme.com", FakeArgs())

    def test_out_of_scope_target_raises_start_error(self, monkeypatch):
        from core.bridge_enrichment import BridgeStartError, run_bridge_phase
        from core.scope_manifest import ScopeResult

        monkeypatch.setenv("BRIDGE_HMAC_KEY", "ab" * 16)

        class FakeClient:
            def scope_check(self, target, scope_token):
                return ScopeResult(in_scope=False, reason="no scope rule matched", manifest_id="x", mode="engagement")
            def enrich(self, target):  # pragma: no cover — should not be called
                raise AssertionError("must not enrich on out-of-scope")
            def close(self):
                pass

        monkeypatch.setattr("core.bridge_enrichment._build_client", lambda *a, **kw: FakeClient())
        with pytest.raises(BridgeStartError, match="not in scope"):
            run_bridge_phase(_config(), "https://elsewhere.test", FakeArgs())

    def test_bridge_unreachable_raises_start_error(self, monkeypatch):
        from core.bridge_enrichment import BridgeStartError, run_bridge_phase
        from modules.reconnaissance.shadowbroker_client import BridgeUnavailableError

        monkeypatch.setenv("BRIDGE_HMAC_KEY", "ab" * 16)

        class FakeClient:
            def scope_check(self, target, scope_token):
                raise BridgeUnavailableError("connection refused")
            def close(self):
                pass

        monkeypatch.setattr("core.bridge_enrichment._build_client", lambda *a, **kw: FakeClient())
        with pytest.raises(BridgeStartError, match="unreachable"):
            run_bridge_phase(_config(), "https://acme.com", FakeArgs())

    def test_happy_path_returns_enrichment_dict(self, monkeypatch):
        from core.bridge_enrichment import run_bridge_phase
        from core.scope_manifest import ScopeResult

        monkeypatch.setenv("BRIDGE_HMAC_KEY", "ab" * 16)

        class FakeClient:
            def scope_check(self, target, scope_token):
                assert scope_token == "engagement-test"
                assert target.value == "https://acme.com"
                return ScopeResult(in_scope=True, reason="matched", manifest_id="m1", mode="engagement")
            def enrich(self, target):
                assert target == "acme.com"  # hostname-only, not URL
                return {"target": "acme.com", "shodan": {"ports": [443]}, "feed_errors": {}}
            def close(self):
                pass

        monkeypatch.setattr("core.bridge_enrichment._build_client", lambda *a, **kw: FakeClient())
        result = run_bridge_phase(_config(), "https://acme.com", FakeArgs())
        assert result is not None
        assert result["target"] == "acme.com"
        assert result["shodan"]["ports"] == [443]

    def test_invalid_base_url_raises_start_error_not_value_error(self, monkeypatch):
        """Codex R3 P3: ShadowbrokerClient ctor raises ValueError on a
        non-http(s) base_url. Without wrapping, the operator sees a generic
        ValueError + traceback instead of the BridgeStartError fail-closed
        path, so deep_eye.py's exit-2 handler never engages and the message
        loses bridge-startup context.
        """
        from core.bridge_enrichment import BridgeStartError, run_bridge_phase

        monkeypatch.setenv("BRIDGE_HMAC_KEY", "ab" * 16)

        # Use the real _build_client (ShadowbrokerClient ctor) — that's
        # exactly the path Codex flagged. CLI override gives a bad URL.
        with pytest.raises(BridgeStartError, match="base_url"):
            run_bridge_phase(
                _config(),
                "https://acme.com",
                FakeArgs(bridge_base_url="ftp://nope.test"),
            )

    def test_cli_overrides_take_precedence_over_config(self, monkeypatch):
        from core.bridge_enrichment import run_bridge_phase
        from core.scope_manifest import ScopeResult

        monkeypatch.setenv("BRIDGE_HMAC_KEY", "ab" * 16)
        seen = {}

        class FakeClient:
            def __init__(self, *, base_url, key_id, key, timeout):
                seen["base_url"] = base_url
                seen["key_id"] = key_id
            def scope_check(self, target, scope_token):
                seen["scope_token"] = scope_token
                return ScopeResult(in_scope=True, reason="ok", manifest_id="m", mode="engagement")
            def enrich(self, target):
                return {"target": "acme.com"}
            def close(self):
                pass

        monkeypatch.setattr("core.bridge_enrichment._build_client",
                            lambda *a, **kw: FakeClient(base_url=kw["base_url"], key_id=kw["key_id"], key=kw["key"], timeout=kw["timeout"]))
        run_bridge_phase(
            _config(),
            "https://acme.com",
            FakeArgs(bridge_scope_token="engagement-override", bridge_base_url="http://other.test"),
        )
        assert seen["base_url"] == "http://other.test"
        assert seen["scope_token"] == "engagement-override"
