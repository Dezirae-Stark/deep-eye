"""HMAC-SHA256 signing for the deep-eye → Shadowbroker bridge channel.

Stdlib-only by design: deep-eye loads this during startup before pip deps
are guaranteed available.

Cross-compatible with backend/services/recon_bridge/hmac_auth.py on the
Shadowbroker side. Both sides MUST stay aligned on:

    canonical_signed_string = METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + SHA256(BODY)
"""

from __future__ import annotations

import hashlib
import hmac


class BridgeAuthError(Exception):
    """Raised when an outbound HMAC check fails locally (rare, mostly defensive)."""


def canonical_signed_string(method: str, path: str, timestamp: int, body: bytes) -> str:
    body_sha = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path}\n{int(timestamp)}\n{body_sha}"


def sign_request(key: bytes, method: str, path: str, timestamp: int, body: bytes) -> str:
    msg = canonical_signed_string(method, path, timestamp, body).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()
