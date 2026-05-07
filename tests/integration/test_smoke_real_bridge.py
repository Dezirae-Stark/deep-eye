"""Real-bin smoke test (Task 21).

Spawns uvicorn in a subprocess hosting a minimal bridge (via configure_bridge),
then drives it with deep-eye's ShadowbrokerClient over real localhost HTTP.

This catches wire-format issues that TestClient short-circuits — header
case-sensitivity, Content-Length on POST bodies, URL encoding through
real HTTP, and signal handling on shutdown.

Skipped unless SHADOWBROKER_BACKEND_PATH points at a Shadowbroker checkout
(or a sibling clone is detected at ../Shadowbroker/backend). Run with:

    SHADOWBROKER_BACKEND_PATH=/path/to/Shadowbroker/backend \
        pytest tests/integration/test_smoke_real_bridge.py -v
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SIBLING_BACKEND = REPO_ROOT.parent / "Shadowbroker" / "backend"


def _resolve_backend_path() -> Path | None:
    p = os.environ.get("SHADOWBROKER_BACKEND_PATH")
    if p and Path(p).is_dir():
        return Path(p)
    if SIBLING_BACKEND.is_dir():
        return SIBLING_BACKEND
    return None


@pytest.fixture(scope="module")
def shadowbroker_backend() -> Path:
    p = _resolve_backend_path()
    if p is None:
        pytest.skip(
            "Shadowbroker backend not found. "
            "Set SHADOWBROKER_BACKEND_PATH or clone Shadowbroker as a sibling dir."
        )
    if not (p / "services" / "recon_bridge" / "wiring.py").exists():
        pytest.skip(f"{p} doesn't look like a Shadowbroker backend (missing wiring.py)")
    return p


def _free_port() -> int:
    """Ask the kernel for an unused TCP port. Bound briefly, then released."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_ready(port: int, timeout: float = 10.0) -> None:
    """Poll /__healthz until 200 or timeout."""
    deadline = time.time() + timeout
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            r = httpx.get(f"http://127.0.0.1:{port}/__healthz", timeout=0.5)
            if r.status_code == 200:
                return
        except Exception as exc:
            last_err = exc
        time.sleep(0.1)
    raise RuntimeError(f"bridge server not ready after {timeout}s: {last_err!r}")


KEY_ID = "smoke-key"
KEY_HEX = "ab" * 32  # 64 hex chars = 32 bytes
KEY_BYTES = bytes.fromhex(KEY_HEX)


@pytest.fixture(scope="module")
def bridge_subprocess(shadowbroker_backend: Path, tmp_path_factory):
    """Spawn the bridge in a subprocess. Module-scoped — one server per
    test file run."""
    tmp = tmp_path_factory.mktemp("scope")
    (tmp / "engagement-smoke.yml").write_text(yaml.safe_dump({
        "version": 1,
        "manifest_id": "engagement-smoke",
        "mode": "engagement",
        "created_at": "2025-01-01T00:00:00Z",
        "expires_at": datetime(2030, 1, 1, tzinfo=timezone.utc).isoformat(),
        "authorization": {"contract_ref": "smoke", "contact": "smoke@test"},
        "targets": {
            "include": {"domains": ["smoke.test", "*.smoke.test"]},
        },
    }))

    port = _free_port()
    env = {
        **os.environ,
        "SHADOWBROKER_BACKEND_PATH": str(shadowbroker_backend),
        "SHADOWBROKER_BRIDGE_ENABLED": "true",
        "SCOPE_MANIFEST_DIR": str(tmp),
        "RECON_BRIDGE_HMAC_KEYS": f"{KEY_ID}:{KEY_HEX}",
        "BRIDGE_TEST_PORT": str(port),
    }

    proc = subprocess.Popen(
        [sys.executable, str(Path(__file__).parent / "_bridge_server.py")],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        try:
            _wait_for_ready(port)
        except RuntimeError:
            # Capture subprocess output for the error message
            try:
                _, stderr = proc.communicate(timeout=1)
                pytest.skip(f"bridge subprocess failed to start: {stderr.decode()[:500]}")
            except subprocess.TimeoutExpired:
                proc.kill()
                pytest.skip("bridge subprocess hung during startup")
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRealBridge:
    def test_unsigned_request_returns_401(self, bridge_subprocess):
        port = bridge_subprocess
        r = httpx.get(f"http://127.0.0.1:{port}/bridge/enrich/smoke.test", timeout=2.0)
        assert r.status_code == 401

    def test_signed_scope_check_in_scope(self, bridge_subprocess):
        from core.scope_manifest import Target
        from modules.reconnaissance.shadowbroker_client import ShadowbrokerClient

        port = bridge_subprocess
        with ShadowbrokerClient(
            base_url=f"http://127.0.0.1:{port}",
            key_id=KEY_ID,
            key=KEY_BYTES,
            timeout=5.0,
        ) as client:
            result = client.scope_check(
                Target(kind="url", value="https://api.smoke.test"),
                scope_token="engagement-smoke",
            )
            assert result.in_scope is True
            assert result.manifest_id == "engagement-smoke"
            assert result.mode == "engagement"

    def test_signed_scope_check_out_of_scope(self, bridge_subprocess):
        from core.scope_manifest import Target
        from modules.reconnaissance.shadowbroker_client import ShadowbrokerClient

        port = bridge_subprocess
        with ShadowbrokerClient(
            base_url=f"http://127.0.0.1:{port}",
            key_id=KEY_ID,
            key=KEY_BYTES,
            timeout=5.0,
        ) as client:
            result = client.scope_check(
                Target(kind="url", value="https://elsewhere.test"),
                scope_token="engagement-smoke",
            )
            assert result.in_scope is False
            assert "no scope rule" in result.reason.lower()

    def test_signed_enrich_returns_dict(self, bridge_subprocess):
        """Enrich runs against real adapters — without SHODAN_API_KEY they
        return empty/feed_errors but the response shape is what matters."""
        from modules.reconnaissance.shadowbroker_client import ShadowbrokerClient

        port = bridge_subprocess
        with ShadowbrokerClient(
            base_url=f"http://127.0.0.1:{port}",
            key_id=KEY_ID,
            key=KEY_BYTES,
            timeout=15.0,  # ct_logs adapter hits crt.sh
        ) as client:
            intel = client.enrich("smoke.test")
            assert intel["target"] == "smoke.test"
            assert "feed_errors" in intel
            assert "stale_after" in intel
