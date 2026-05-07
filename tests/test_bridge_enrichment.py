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
    individual keys via kwargs."""
    base = {
        "shadowbroker_bridge": {
            "enabled": True,
            "base_url": "http://bridge.test",
            "key_id": "test-key",
            "scope_token": "engagement-test",
            "scope_manifest_path": "config/scope/example-engagement.yml",
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
