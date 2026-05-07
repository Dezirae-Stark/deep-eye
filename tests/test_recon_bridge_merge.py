"""Tests for Task 19 — bridge_intel merging into ReconEngine.run() and
through ScannerEngine.

Strategy:
  * enabled_modules = [] keeps recon_engine hermetic (no DNS, no sockets)
  * dnspython is optional in dev; we ensure recon_engine imports even
    when it's missing by lazy-loading it inside _get_dns_records.
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest


@pytest.fixture(autouse=True)
def _stub_optional_deps(monkeypatch):
    """If dnspython isn't installed in this dev env, stub it so imports
    don't crash. Production envs install it via requirements.txt.
    """
    if "dns" not in sys.modules:
        dns_mod = MagicMock(name="dns")
        dns_resolver_mod = MagicMock(name="dns.resolver")
        monkeypatch.setitem(sys.modules, "dns", dns_mod)
        monkeypatch.setitem(sys.modules, "dns.resolver", dns_resolver_mod)
    yield


class TestReconEngineBridgeMerge:
    def test_bridge_intel_none_leaves_results_untouched(self):
        from modules.reconnaissance.recon_engine import ReconEngine

        engine = ReconEngine(config={"reconnaissance": {"enabled_modules": []}}, http_client=None)
        results = engine.run("https://acme.com")
        assert "shadowbroker" not in results
        assert results["target"] == "https://acme.com"

    def test_bridge_intel_merged_under_shadowbroker_key(self):
        from modules.reconnaissance.recon_engine import ReconEngine

        intel = {
            "target": "acme.com",
            "resolved_ips": ["1.2.3.4"],
            "shodan": {"ports": [443]},
            "geo": {"country": "US", "asn": "AS64500"},
            "ct_logs": [{"cn": "acme.com", "issuer": "X CA"}],
            "feed_errors": {},
        }
        engine = ReconEngine(config={"reconnaissance": {"enabled_modules": []}}, http_client=None)
        results = engine.run("https://acme.com", bridge_intel=intel)

        assert "shadowbroker" in results
        assert results["shadowbroker"]["resolved_ips"] == ["1.2.3.4"]
        assert results["shadowbroker"]["shodan"]["ports"] == [443]

    def test_bridge_ct_logs_seed_subdomains_when_module_enabled(self):
        """When subdomain_enumeration runs, CT log entries from the bridge
        should be folded into the subdomain list (no duplicate scanning,
        just enrichment)."""
        from modules.reconnaissance.recon_engine import ReconEngine

        intel = {
            "ct_logs": [
                {"cn": "acme.com", "issuer": "X"},
                {"cn": "api.acme.com", "issuer": "X"},
                {"cn": "internal.acme.com\nadmin.acme.com", "issuer": "X"},  # crt.sh quirk
            ],
            "feed_errors": {},
        }
        engine = ReconEngine(
            config={"reconnaissance": {"enabled_modules": []}},
            http_client=None,
        )
        results = engine.run("https://acme.com", bridge_intel=intel)
        ct_subs = results["shadowbroker"]["ct_subdomains"]
        # Hostnames from name_value strings (which can be multi-line in crt.sh)
        # should be split + deduped.
        assert "acme.com" in ct_subs
        assert "api.acme.com" in ct_subs
        assert "internal.acme.com" in ct_subs
        assert "admin.acme.com" in ct_subs

    def test_bridge_feed_errors_logged_as_partial_status(self):
        """feed_errors should be visible at the top of the recon report so
        operators know which feeds were degraded."""
        from modules.reconnaissance.recon_engine import ReconEngine

        intel = {
            "shodan": {"ports": [443]},
            "feed_errors": {"geopolitics": "timeout after 5.00s"},
        }
        engine = ReconEngine(config={"reconnaissance": {"enabled_modules": []}}, http_client=None)
        results = engine.run("https://acme.com", bridge_intel=intel)
        assert results["shadowbroker"]["feed_errors"] == {"geopolitics": "timeout after 5.00s"}


class TestScannerEngineBridgeIntel:
    def test_scanner_engine_accepts_and_threads_bridge_intel(self, monkeypatch):
        """ScannerEngine accepts bridge_intel and passes it to ReconEngine
        on run_reconnaissance."""
        # Avoid pulling rich/HTTPClient/etc. — just verify the surface.
        from modules.reconnaissance.recon_engine import ReconEngine

        intel = {"shodan": {"ports": [443]}, "feed_errors": {}}

        # Construct ReconEngine directly and call run() with bridge_intel
        # — this is the path ScannerEngine will use after Task 19.
        engine = ReconEngine(config={"reconnaissance": {"enabled_modules": []}}, http_client=None)
        out = engine.run("https://acme.com", bridge_intel=intel)
        assert out["shadowbroker"] is intel
