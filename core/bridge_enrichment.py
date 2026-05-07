"""Bridge enrichment phase — runs before recon proper.

Enforces the operator's three fail-closed rules (Task 18):
  1. BRIDGE_HMAC_KEY env var unset → BridgeStartError
  2. scope_check returns in_scope=False → BridgeStartError
  3. Bridge unreachable / 5xx → BridgeStartError

Also returns the enriched intel dict for the recon engine to consume in
Task 19. Returns None when the bridge is disabled (no work to do).

The CLI surface (deep_eye.py argparse) provides:
    --no-bridge              force disable, even if config has enabled=true
    --bridge-scope-token X   override config's scope_token
    --bridge-base-url X      override config's base_url
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional, Protocol
from urllib.parse import urlparse

from core.scope_manifest import Target

logger = logging.getLogger(__name__)


class BridgeStartError(Exception):
    """Raised when the bridge phase cannot complete safely.

    deep_eye.py's main() catches this and exits non-zero with the message.
    Operators see this when:
      - BRIDGE_HMAC_KEY is unset/invalid
      - the target is out of scope
      - the bridge is unreachable while enabled
    """


class _ArgsProto(Protocol):
    no_bridge: bool
    bridge_scope_token: Optional[str]
    bridge_base_url: Optional[str]


def run_bridge_phase(
    config: dict[str, Any],
    target_url: str,
    args: _ArgsProto,
) -> Optional[dict[str, Any]]:
    """Execute the bridge enrichment phase.

    Returns None if bridge is disabled. Returns the enrichment dict on
    success. Raises BridgeStartError on any failure mode the operator
    chose to fail-closed on.
    """
    bridge_cfg = config.get("shadowbroker_bridge") or {}
    if not bridge_cfg.get("enabled"):
        logger.debug("shadowbroker_bridge: disabled in config, skipping")
        return None
    if getattr(args, "no_bridge", False):
        logger.info("shadowbroker_bridge: disabled via --no-bridge flag")
        return None

    secret = _load_secret_from_env()  # raises BridgeStartError on miss/bad hex
    base_url = args.bridge_base_url or bridge_cfg["base_url"]
    key_id = bridge_cfg["key_id"]
    scope_token = args.bridge_scope_token or bridge_cfg["scope_token"]
    timeout = float(bridge_cfg.get("timeout", 10.0))

    client = _build_client(
        base_url=base_url,
        key_id=key_id,
        key=secret,
        timeout=timeout,
    )
    try:
        # 1) Scope-check the target. Fail-closed if out of scope.
        result = _safe_scope_check(client, target_url, scope_token)
        if not result.in_scope:
            raise BridgeStartError(
                f"target {target_url!r} not in scope for {scope_token!r}: {result.reason}"
            )
        logger.info(
            "bridge scope check OK: manifest_id=%s mode=%s reason=%s",
            result.manifest_id, result.mode, result.reason,
        )

        # 2) Enrich. The bridge accepts hostnames; strip URL.
        host = _target_to_host(target_url)
        intel = _safe_enrich(client, host)
        feed_errors = intel.get("feed_errors") or {}
        if feed_errors:
            logger.warning("bridge enrichment partial: feed_errors=%s", feed_errors)
        return intel
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Internals — extracted so tests can monkeypatch _build_client cleanly.
# ---------------------------------------------------------------------------

def _build_client(*, base_url: str, key_id: str, key: bytes, timeout: float):
    """Construct the ShadowbrokerClient. Test seam — tests monkeypatch this."""
    from modules.reconnaissance.shadowbroker_client import ShadowbrokerClient

    return ShadowbrokerClient(
        base_url=base_url,
        key_id=key_id,
        key=key,
        timeout=timeout,
    )


def _safe_scope_check(client, target_url: str, scope_token: str):
    from modules.reconnaissance.shadowbroker_client import (
        BridgeAuthError,
        BridgeScopeError,
        BridgeUnavailableError,
    )

    target = Target(kind="url", value=target_url)
    try:
        return client.scope_check(target, scope_token)
    except BridgeUnavailableError as exc:
        raise BridgeStartError(f"bridge unreachable during scope check: {exc}") from exc
    except BridgeAuthError as exc:
        raise BridgeStartError(f"bridge auth failed during scope check: {exc}") from exc
    except BridgeScopeError as exc:
        raise BridgeStartError(f"bridge rejected scope check: {exc}") from exc


def _safe_enrich(client, host: str) -> dict[str, Any]:
    from modules.reconnaissance.shadowbroker_client import (
        BridgeAuthError,
        BridgeScopeError,
        BridgeUnavailableError,
    )

    try:
        return client.enrich(host)
    except BridgeUnavailableError as exc:
        raise BridgeStartError(f"bridge unreachable during enrich: {exc}") from exc
    except BridgeAuthError as exc:
        raise BridgeStartError(f"bridge auth failed during enrich: {exc}") from exc
    except BridgeScopeError as exc:
        # 4xx during enrich is unusual — surface it but classify as a hard fail.
        raise BridgeStartError(f"bridge rejected enrich: {exc}") from exc


def _load_secret_from_env() -> bytes:
    raw = os.environ.get("BRIDGE_HMAC_KEY", "").strip()
    if not raw:
        raise BridgeStartError(
            "shadowbroker_bridge.enabled=true but BRIDGE_HMAC_KEY env var is unset. "
            "Export it: `export BRIDGE_HMAC_KEY=<hex-secret>`"
        )
    try:
        return bytes.fromhex(raw)
    except ValueError as exc:
        raise BridgeStartError(
            f"BRIDGE_HMAC_KEY is not valid hex: {exc}"
        ) from exc


def _target_to_host(target_url: str) -> str:
    """Convert the deep-eye CLI target into a bare hostname for /bridge/enrich."""
    parsed = urlparse(target_url)
    return parsed.hostname or target_url
