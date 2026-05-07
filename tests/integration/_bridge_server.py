"""Minimal bridge-only uvicorn launcher used by test_smoke_real_bridge.

Runs configure_bridge against a fresh FastAPI() and serves it on 127.0.0.1
at a port chosen via $BRIDGE_TEST_PORT. All Shadowbroker env vars
(SHADOWBROKER_BRIDGE_ENABLED, SCOPE_MANIFEST_DIR, RECON_BRIDGE_HMAC_KEYS)
must already be set in the launching process — they are passed through.

This script does NOT depend on the rest of Shadowbroker's monolith; it
imports only services.recon_bridge.wiring and routers.recon_bridge.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    sb_backend = os.environ.get("SHADOWBROKER_BACKEND_PATH")
    if not sb_backend:
        print("SHADOWBROKER_BACKEND_PATH must be set", file=sys.stderr)
        return 2
    sys.path.insert(0, sb_backend)

    from fastapi import FastAPI  # noqa: E402  — must come after sys.path mod
    from services.recon_bridge.wiring import configure_bridge  # noqa: E402
    import uvicorn  # noqa: E402

    app = FastAPI()
    configure_bridge(app)

    @app.get("/__healthz")
    def _healthz():  # tiny readiness probe
        return {"ok": True}

    port = int(os.environ.get("BRIDGE_TEST_PORT", "18800"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
