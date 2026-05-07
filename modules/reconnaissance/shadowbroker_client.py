"""ShadowbrokerClient — synchronous HTTP client for the Shadowbroker bridge.

Two operations:
    scope_check(target, scope_token) -> ScopeResult
    enrich(target)                   -> dict[str, Any]

Both sign every request with HMAC-SHA256 using the canonical string
defined in modules.reconnaissance.hmac_auth, which is cross-compatible
with backend/services/recon_bridge/hmac_auth.py.

Path-signing contract (must match the bridge's _enforce_hmac):
    * Sign the *decoded* canonical path (e.g. "/bridge/enrich/api.acme.com")
    * URL-encode the target only for wire transport
This lets request.url.path on the Starlette side match without forcing
clients to pre-encode targets before HMAC.

Failure model: typed exceptions per scenario.
    BridgeAuthError         — 401 from the bridge
    BridgeScopeError        — 404 (unknown scope_token) or scope-rejection 4xx
    BridgeUnavailableError  — 5xx, network failure, or timeout
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional
from urllib.parse import quote

import httpx

from core.scope_manifest import ScopeResult, Target
from modules.reconnaissance.hmac_auth import BridgeAuthError, sign_request

logger = logging.getLogger(__name__)


class BridgeError(Exception):
    """Base for all bridge client errors."""


class BridgeScopeError(BridgeError):
    """The bridge could not resolve the requested scope (404, malformed)."""


class BridgeUnavailableError(BridgeError):
    """The bridge is unreachable, timing out, or returning 5xx."""


class ShadowbrokerClient:
    def __init__(
        self,
        *,
        base_url: str,
        key_id: str,
        key: bytes,
        timeout: float = 10.0,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(f"base_url must be http(s)://, got {base_url!r}")
        self._base_url = base_url.rstrip("/")
        self._key_id = key_id
        self._key = key
        self._owns_client = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout)

    def close(self) -> None:
        if self._owns_client:
            self._http.close()

    def __enter__(self) -> "ShadowbrokerClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scope_check(self, target: Target, scope_token: str) -> ScopeResult:
        body_obj = {
            "target": {"kind": target.kind, "value": target.value},
            "scope_token": scope_token,
        }
        body = json.dumps(body_obj).encode("utf-8")
        path = "/bridge/scope/check"
        resp = self._signed_request("POST", path, path, body=body, json_body=True)

        if resp.status_code == 200:
            data = resp.json()
            return ScopeResult(
                in_scope=bool(data.get("in_scope")),
                reason=str(data.get("reason", "")),
                manifest_id=str(data.get("manifest_id", "")),
                mode=str(data.get("mode", "")),
            )
        self._raise_for_status(resp, op="scope_check")

    def enrich(self, target: str) -> dict[str, Any]:
        # Decoded canonical path (signed); encoded wire path (sent).
        canonical_path = f"/bridge/enrich/{target}"
        wire_path = f"/bridge/enrich/{quote(target, safe='')}"
        resp = self._signed_request("GET", canonical_path, wire_path, body=b"")

        if resp.status_code == 200:
            return resp.json()
        self._raise_for_status(resp, op="enrich")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _signed_request(
        self,
        method: str,
        canonical_path: str,
        wire_path: str,
        *,
        body: bytes,
        json_body: bool = False,
    ) -> httpx.Response:
        ts = int(time.time())
        sig = sign_request(self._key, method, canonical_path, ts, body)
        headers = {
            "X-Bridge-Key-Id": self._key_id,
            "X-Bridge-Timestamp": str(ts),
            "X-Bridge-Signature": sig,
        }
        if json_body:
            headers["Content-Type"] = "application/json"
        url = f"{self._base_url}{wire_path}"
        try:
            return self._http.request(method, url, headers=headers, content=body or None)
        except httpx.TimeoutException as exc:
            raise BridgeUnavailableError(f"{method} {wire_path}: timeout: {exc}") from exc
        except httpx.HTTPError as exc:
            raise BridgeUnavailableError(f"{method} {wire_path}: {exc}") from exc

    def _raise_for_status(self, resp: httpx.Response, *, op: str) -> "Any":
        detail = self._extract_detail(resp)
        if resp.status_code == 401:
            raise BridgeAuthError(f"{op}: {detail}")
        if resp.status_code == 404:
            raise BridgeScopeError(f"{op}: {detail}")
        if 500 <= resp.status_code < 600 or resp.status_code == 503:
            raise BridgeUnavailableError(f"{op}: HTTP {resp.status_code}: {detail}")
        # Anything else (4xx other than 401/404) — treat as scope/usage failure.
        raise BridgeScopeError(f"{op}: HTTP {resp.status_code}: {detail}")

    @staticmethod
    def _extract_detail(resp: httpx.Response) -> str:
        try:
            data = resp.json()
            if isinstance(data, dict) and "detail" in data:
                return str(data["detail"])
        except (ValueError, KeyError):
            pass
        return resp.text[:200]
