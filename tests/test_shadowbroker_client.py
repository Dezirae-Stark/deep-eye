"""Tests for the ShadowbrokerClient — deep-eye's HTTP client for the bridge.

Uses respx to intercept httpx calls so we can assert on exact wire bytes
(headers, URL, body) without standing up a real bridge.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from core.scope_manifest import Target


KEY_ID = "deep-eye-test"
KEY_BYTES = bytes.fromhex("ab" * 32)  # 32-byte secret
BASE = "http://bridge.test"


@pytest.fixture
def client():
    """A fresh ShadowbrokerClient. Tests can use this or build their own."""
    from modules.reconnaissance.shadowbroker_client import ShadowbrokerClient

    c = ShadowbrokerClient(base_url=BASE, key_id=KEY_ID, key=KEY_BYTES, timeout=2.0)
    yield c
    c.close()


# ---------------------------------------------------------------------------
# scope_check
# ---------------------------------------------------------------------------

class TestScopeCheck:
    @respx.mock
    def test_in_scope_returns_scope_result(self, client):
        respx.post(f"{BASE}/bridge/scope/check").mock(
            return_value=httpx.Response(200, json={
                "in_scope": True,
                "reason": "matched domain pattern *.acme.com",
                "manifest_id": "engagement-x",
                "mode": "engagement",
            })
        )
        result = client.scope_check(
            Target(kind="url", value="https://api.acme.com"),
            scope_token="engagement-x",
        )
        assert result.in_scope is True
        assert result.manifest_id == "engagement-x"
        assert result.mode == "engagement"

    @respx.mock
    def test_unknown_scope_token_raises_scope_error(self, client):
        from modules.reconnaissance.shadowbroker_client import BridgeScopeError

        respx.post(f"{BASE}/bridge/scope/check").mock(
            return_value=httpx.Response(404, json={"detail": "no manifest for scope_token='gone'"})
        )
        with pytest.raises(BridgeScopeError, match="no manifest"):
            client.scope_check(
                Target(kind="url", value="https://acme.com"),
                scope_token="gone",
            )

    @respx.mock
    def test_auth_failure_raises_auth_error(self, client):
        from modules.reconnaissance.shadowbroker_client import BridgeAuthError

        respx.post(f"{BASE}/bridge/scope/check").mock(
            return_value=httpx.Response(401, json={"detail": "signature mismatch"})
        )
        with pytest.raises(BridgeAuthError):
            client.scope_check(
                Target(kind="url", value="https://acme.com"),
                scope_token="x",
            )

    @respx.mock
    def test_request_carries_signed_headers(self, client):
        route = respx.post(f"{BASE}/bridge/scope/check").mock(
            return_value=httpx.Response(200, json={
                "in_scope": True, "reason": "ok", "manifest_id": "x", "mode": "engagement",
            })
        )
        client.scope_check(Target(kind="url", value="https://acme.com"), scope_token="x")

        sent = route.calls.last.request
        assert sent.headers["X-Bridge-Key-Id"] == KEY_ID
        assert sent.headers["X-Bridge-Timestamp"].isdigit()
        # 64 hex chars = SHA-256 hex digest
        assert len(sent.headers["X-Bridge-Signature"]) == 64
        # Body is the JSON we serialized.
        body = json.loads(sent.content)
        assert body["target"]["value"] == "https://acme.com"


# ---------------------------------------------------------------------------
# enrich
# ---------------------------------------------------------------------------

class TestEnrich:
    @respx.mock
    def test_returns_normalized_intel(self, client):
        respx.get(f"{BASE}/bridge/enrich/api.acme.com").mock(
            return_value=httpx.Response(200, json={
                "target": "api.acme.com",
                "resolved_ips": ["203.0.113.10"],
                "shodan": {"ports": [443]},
                "geo": {"country": "US", "asn": "AS64500"},
                "region_dossier": None,
                "geopolitics_alerts": [],
                "ct_logs": [{"cn": "api.acme.com", "issuer": "CA1"}],
                "feed_errors": {},
                "stale_after": "2026-05-07T12:00:00+00:00",
            })
        )
        intel = client.enrich("api.acme.com")
        assert intel["target"] == "api.acme.com"
        assert intel["resolved_ips"] == ["203.0.113.10"]
        assert intel["geo"]["asn"] == "AS64500"

    @respx.mock
    def test_url_target_is_url_encoded_on_wire(self, client):
        """Client must URL-encode the target for HTTP transport — /
        and : in the target would otherwise corrupt the path."""
        target = "https://api.acme.com/health"
        # The canonical (decoded) path is what the bridge will sign-check against.
        canonical_path = f"/bridge/enrich/{target}"
        # The encoded (wire) URL is what httpx must actually send.
        encoded_path = "/bridge/enrich/https%3A%2F%2Fapi.acme.com%2Fhealth"

        route = respx.get(f"{BASE}{encoded_path}").mock(
            return_value=httpx.Response(200, json={
                "target": target, "resolved_ips": [], "shodan": None, "geo": None,
                "region_dossier": None, "geopolitics_alerts": [],
                "ct_logs": [], "feed_errors": {}, "stale_after": "2026-05-07T12:00:00+00:00",
            })
        )
        client.enrich(target)
        assert route.called

    @respx.mock
    def test_signature_signs_decoded_path(self, client):
        """The X-Bridge-Signature must be over the *decoded* canonical path —
        Task 15 documented this contract on the Shadowbroker side."""
        from modules.reconnaissance.hmac_auth import sign_request

        target = "https://api.acme.com/health"
        encoded_path = "/bridge/enrich/https%3A%2F%2Fapi.acme.com%2Fhealth"

        captured: dict = {}
        route = respx.get(f"{BASE}{encoded_path}")

        def _capture(request):
            captured["request"] = request
            return httpx.Response(200, json={
                "target": target, "resolved_ips": [], "shodan": None, "geo": None,
                "region_dossier": None, "geopolitics_alerts": [],
                "ct_logs": [], "feed_errors": {}, "stale_after": "2026-05-07T12:00:00+00:00",
            })

        route.side_effect = _capture
        client.enrich(target)

        ts = int(captured["request"].headers["X-Bridge-Timestamp"])
        expected = sign_request(KEY_BYTES, "GET", f"/bridge/enrich/{target}", ts, b"")
        assert captured["request"].headers["X-Bridge-Signature"] == expected

    @respx.mock
    def test_503_raises_unavailable(self, client):
        from modules.reconnaissance.shadowbroker_client import BridgeUnavailableError

        respx.get(f"{BASE}/bridge/enrich/x.test").mock(
            return_value=httpx.Response(503, json={"detail": "enrichment aggregator not initialized"})
        )
        with pytest.raises(BridgeUnavailableError):
            client.enrich("x.test")

    @respx.mock
    def test_network_error_raises_unavailable(self, client):
        from modules.reconnaissance.shadowbroker_client import BridgeUnavailableError

        respx.get(f"{BASE}/bridge/enrich/x.test").mock(side_effect=httpx.ConnectError("boom"))
        with pytest.raises(BridgeUnavailableError, match="boom"):
            client.enrich("x.test")

    @respx.mock
    def test_timeout_raises_unavailable(self, client):
        from modules.reconnaissance.shadowbroker_client import BridgeUnavailableError

        respx.get(f"{BASE}/bridge/enrich/x.test").mock(side_effect=httpx.ReadTimeout("slow"))
        with pytest.raises(BridgeUnavailableError):
            client.enrich("x.test")
