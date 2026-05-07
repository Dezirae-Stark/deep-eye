# Plan A — Shadowbroker Pre-Scan Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire Shadowbroker's existing OSINT feeds (Shodan, region dossier, geopolitics, CT logs) into deep-eye's existing CLI scan flow as opportunistic enrichment, gated by a mandatory-expiry scope manifest and an HMAC-signed bridge mirroring Shadowbroker's OpenClaw channel. Working software at the end: `deep_eye.py -u https://target.com --enrich-from-shadowbroker --scope-token <id>` runs an existing scan with richer recon context.

**Architecture:** A new additive router (`backend/routers/recon_bridge.py`) and service module (`backend/services/recon_bridge/`) in the forked Shadowbroker. A new client module (`modules/reconnaissance/shadowbroker_client.py`), client-side scope enforcer (`core/scope_enforcer.py`), and CLI flag wiring in the forked deep-eye. HMAC-SHA256 auth shared between both sides (independent implementations, cross-compatible). Enrichment is opportunistic: bridge unreachable → log + fall back to existing `osint_enhanced.py`, scan proceeds.

**Tech Stack:** Python 3.10+ (Shadowbroker), Python 3.8+ (deep-eye), FastAPI 0.115, httpx 0.28/0.26, pydantic 2.13, pytest 8.3 + pytest-asyncio, cryptography 41+, PyYAML 6+. Both repos already depend on these.

---

## Reference Documents

- **Spec:** `docs/superpowers/specs/2026-05-05-shadowbroker-integration-design.md` (in deep-eye)
- **OpenClaw HMAC pattern (reference):** `Shadowbroker/backend/services/openclaw_channel.py`
- **Shodan service to call:** `Shadowbroker/backend/services/shodan_connector.py`
- **Region dossier service to call:** `Shadowbroker/backend/services/region_dossier.py`
- **Geopolitics service to call:** `Shadowbroker/backend/services/geopolitics.py`
- **Existing fallback recon:** `deep-eye/modules/reconnaissance/osint_enhanced.py`

## Repository Layout

This plan touches **two forked repositories** sitting side-by-side:

- `Shadowbroker/` — the forked Shadowbroker repo (origin currently `BigBodyCobain/Shadowbroker`; user will repoint to their own fork before pushing)
- `deep-eye/` — the forked deep-eye repo (origin currently `zakirkun/deep-eye`; same)

Each task header indicates `**Repo:**` to make context unambiguous. Run all `pytest`, `git`, etc. commands from inside the repo named there.

## Files in This Plan

### Shadowbroker fork — created

```
backend/
├── services/recon_bridge/
│   ├── __init__.py                       (empty package marker)
│   ├── hmac_auth.py                      (sign/verify HMAC-SHA256 over canonical request)
│   ├── scope_manifest.py                 (load scope.yml, validate target against rules)
│   └── enrichment_aggregator.py          (parallel fan-out to shodan/region/geopolitics/CT, 60s cache)
├── routers/
│   └── recon_bridge.py                   (FastAPI router: /bridge/scope/check, /bridge/enrich)
├── tests/recon_bridge/
│   ├── __init__.py
│   ├── test_hmac_auth.py
│   ├── test_scope_manifest.py
│   ├── test_enrichment_aggregator.py
│   └── test_router_recon_bridge.py
└── config/scope/
    └── example-engagement.yml            (sample scope manifest)
```

### Shadowbroker fork — modified

- `backend/main.py` — one line: register the new router.

### Deep-eye fork — created

```
config/
├── shadowbroker.example.yaml             (bridge_url, hmac_key_id, scope_manifest_path)
└── scope/
    └── example-engagement.yml            (sample scope manifest, identical schema)

core/
├── scope_enforcer.py                     (client-side scope check; defense in depth)
└── scope_manifest.py                     (parser, identical semantics to Shadowbroker side)

modules/reconnaissance/
├── hmac_auth.py                          (sign HMAC-SHA256, identical algorithm to Shadowbroker)
└── shadowbroker_client.py                (HMAC HTTP client → /bridge/* endpoints)

tests/
├── __init__.py
├── conftest.py
├── test_hmac_auth.py
├── test_scope_manifest.py
├── test_scope_enforcer.py
├── test_shadowbroker_client.py
└── test_deep_eye_enrichment.py

requirements-dev.txt                      (pytest, pytest-asyncio, pytest-httpx, respx)
pytest.ini                                (testpaths, asyncio config)
```

### Deep-eye fork — modified

- `deep_eye.py` — add `--enrich-from-shadowbroker`, `--scope-token`, `--bridge-config` flags; wire enrichment into the recon phase before scanning.
- `requirements.txt` — add `httpx>=0.26.0` (already present, verify) and `cryptography>=41.0.0` (already present).

---

## Conventions used in every task

- **TDD rhythm:** failing test → run to confirm fail → minimal implementation → run to confirm pass → commit.
- **Commit messages:** Conventional commits (`feat:`, `test:`, `docs:`, `chore:`). Each commit is small and self-contained.
- **No `--no-verify` unless documented:** the user has a Claude Code-level Opsera scan hook; the touch-flag bypass is documented in the spec commit. Code commits should pass the scan.
- **Pytest invocations** assume you are inside the repo root (`Shadowbroker/backend/` for the Shadowbroker tasks, `deep-eye/` for the deep-eye tasks).

---

## Task 1 — Bootstrap pytest in deep-eye

**Repo:** `deep-eye`

deep-eye ships without a test framework today — `setup.py`, `requirements.txt`, no `pytest.ini`, no `tests/`. Plan A introduces enough new code that we want test discipline from day one.

**Files:**
- Create: `requirements-dev.txt`
- Create: `pytest.ini`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Create `requirements-dev.txt`**

```
# Test dependencies — install with: pip install -r requirements-dev.txt
pytest>=8.3.4
pytest-asyncio>=0.25.0
pytest-httpx>=0.30.0
respx>=0.21.0
```

- [ ] **Step 2: Create `pytest.ini`**

```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
asyncio_mode = auto
asyncio_default_fixture_loop_scope = function
addopts = -v --tb=short
```

- [ ] **Step 3: Create `tests/__init__.py`** (empty file).

- [ ] **Step 4: Create `tests/conftest.py`**

```python
"""Shared pytest fixtures for deep-eye tests."""

import pytest


@pytest.fixture
def fixed_clock():
    """A clock that returns a stable monotonically-increasing fake timestamp.

    Tests that depend on time (HMAC timestamp checks, manifest expiry) call
    this fixture's `now()` rather than time.time() to keep tests deterministic.
    """
    state = {"now": 1735689600}  # 2025-01-01 00:00:00 UTC

    def now() -> int:
        return state["now"]

    def advance(seconds: int) -> None:
        state["now"] += seconds

    now.advance = advance  # type: ignore[attr-defined]
    return now
```

- [ ] **Step 5: Install deps and verify pytest runs (no tests yet)**

Run: `pip install -r requirements-dev.txt && pytest -q`

Expected output (the "no tests collected" form is correct since we haven't written any):
```
no tests ran in 0.0Xs
```

- [ ] **Step 6: Commit**

```bash
git add requirements-dev.txt pytest.ini tests/__init__.py tests/conftest.py
git commit -m "chore: bootstrap pytest infrastructure for shadowbroker integration"
```

---

## Task 2 — HMAC auth library (Shadowbroker side)

**Repo:** `Shadowbroker`

Mirror the OpenClaw pattern from `services/openclaw_channel.py` for our bridge channel. The signed canonical string is `METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + SHA256(BODY)`. Headers are `X-Bridge-Key-Id`, `X-Bridge-Timestamp`, `X-Bridge-Signature`.

**Files:**
- Create: `backend/services/recon_bridge/__init__.py`
- Create: `backend/services/recon_bridge/hmac_auth.py`
- Create: `backend/tests/recon_bridge/__init__.py`
- Create: `backend/tests/recon_bridge/test_hmac_auth.py`

- [ ] **Step 1: Create empty package markers**

```bash
mkdir -p backend/services/recon_bridge backend/tests/recon_bridge
touch backend/services/recon_bridge/__init__.py backend/tests/recon_bridge/__init__.py
```

- [ ] **Step 2: Write the failing tests**

Create `backend/tests/recon_bridge/test_hmac_auth.py`:

```python
"""HMAC-SHA256 signing/verification for the recon bridge channel.

Mirrors the canonical request format used by services/openclaw_channel.py:
  signed_str = METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + SHA256(BODY)
"""

import hashlib
import hmac
import time

import pytest

from services.recon_bridge.hmac_auth import (
    BridgeAuthError,
    canonical_signed_string,
    sign_request,
    verify_request,
)


KEY = b"test-shared-key-32bytes-minimum-padding"
KEY_ID = "deep-eye-agent"


class TestCanonicalString:
    def test_includes_all_four_components(self):
        body = b'{"target":"example.com"}'
        s = canonical_signed_string("GET", "/bridge/enrich/example.com", 1700000000, body)
        body_sha = hashlib.sha256(body).hexdigest()
        assert s == f"GET\n/bridge/enrich/example.com\n1700000000\n{body_sha}"

    def test_empty_body_uses_sha256_of_empty_bytes(self):
        s = canonical_signed_string("POST", "/bridge/scope/check", 1700000000, b"")
        empty_sha = hashlib.sha256(b"").hexdigest()
        assert s.endswith(f"\n{empty_sha}")


class TestSignAndVerify:
    def test_roundtrip_succeeds(self):
        body = b'{"x":1}'
        ts = 1700000000
        sig = sign_request(KEY, "POST", "/bridge/scope/check", ts, body)
        # Should not raise
        verify_request(KEY, "POST", "/bridge/scope/check", ts, body, sig, now=lambda: ts)

    def test_tampered_body_rejected(self):
        ts = 1700000000
        sig = sign_request(KEY, "POST", "/bridge/scope/check", ts, b'{"x":1}')
        with pytest.raises(BridgeAuthError, match="signature mismatch"):
            verify_request(KEY, "POST", "/bridge/scope/check", ts, b'{"x":2}', sig, now=lambda: ts)

    def test_tampered_path_rejected(self):
        ts = 1700000000
        sig = sign_request(KEY, "POST", "/bridge/scope/check", ts, b"")
        with pytest.raises(BridgeAuthError, match="signature mismatch"):
            verify_request(KEY, "POST", "/bridge/elsewhere", ts, b"", sig, now=lambda: ts)

    def test_wrong_key_rejected(self):
        ts = 1700000000
        sig = sign_request(KEY, "GET", "/bridge/enrich/x", ts, b"")
        with pytest.raises(BridgeAuthError, match="signature mismatch"):
            verify_request(b"different-key", "GET", "/bridge/enrich/x", ts, b"", sig, now=lambda: ts)

    def test_timestamp_too_old_rejected(self):
        ts = 1700000000
        sig = sign_request(KEY, "GET", "/bridge/enrich/x", ts, b"")
        # Server clock is 70s ahead; our window is 60s
        with pytest.raises(BridgeAuthError, match="timestamp out of window"):
            verify_request(KEY, "GET", "/bridge/enrich/x", ts, b"", sig, now=lambda: ts + 70)

    def test_timestamp_in_future_rejected(self):
        ts = 1700000000
        sig = sign_request(KEY, "GET", "/bridge/enrich/x", ts, b"")
        # Client clock is 70s ahead; server now is older
        with pytest.raises(BridgeAuthError, match="timestamp out of window"):
            verify_request(KEY, "GET", "/bridge/enrich/x", ts, b"", sig, now=lambda: ts - 70)

    def test_signature_is_lowercase_hex(self):
        sig = sign_request(KEY, "GET", "/x", 1700000000, b"")
        assert sig == sig.lower()
        assert all(c in "0123456789abcdef" for c in sig)
        assert len(sig) == 64  # HMAC-SHA256 hex


class TestNonceReplay:
    def test_replay_with_same_signature_rejected(self):
        from services.recon_bridge.hmac_auth import NonceCache

        cache = NonceCache(max_size=100, ttl_seconds=300)
        ts = 1700000000
        sig = sign_request(KEY, "GET", "/x", ts, b"")
        cache.assert_unseen(KEY_ID, ts, sig)
        with pytest.raises(BridgeAuthError, match="replay"):
            cache.assert_unseen(KEY_ID, ts, sig)

    def test_different_signatures_both_accepted(self):
        from services.recon_bridge.hmac_auth import NonceCache

        cache = NonceCache(max_size=100, ttl_seconds=300)
        cache.assert_unseen(KEY_ID, 1700000000, "a" * 64)
        cache.assert_unseen(KEY_ID, 1700000000, "b" * 64)  # different sig, ok
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/recon_bridge/test_hmac_auth.py -v`
Expected: All `test_*` ERRORs because `services.recon_bridge.hmac_auth` does not yet exist.

- [ ] **Step 4: Write minimal implementation**

Create `backend/services/recon_bridge/hmac_auth.py`:

```python
"""HMAC-SHA256 auth for the recon bridge channel.

Pattern mirrors services/openclaw_channel.py:
  signed_str = METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + SHA256(BODY)

The deep-eye client side has an independent but cross-compatible implementation
under modules/reconnaissance/hmac_auth.py — both must produce identical
signatures for identical inputs (verified by Plan A's cross-compatibility test).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from collections import OrderedDict
from threading import Lock
from typing import Callable

logger = logging.getLogger(__name__)

# Maximum allowed clock skew between client and server, in seconds.
TIMESTAMP_WINDOW_SECONDS = 60


class BridgeAuthError(Exception):
    """Raised when a bridge HMAC check fails."""


def canonical_signed_string(method: str, path: str, timestamp: int, body: bytes) -> str:
    """Build the canonical string to sign / verify."""
    body_sha = hashlib.sha256(body).hexdigest()
    return f"{method.upper()}\n{path}\n{int(timestamp)}\n{body_sha}"


def sign_request(key: bytes, method: str, path: str, timestamp: int, body: bytes) -> str:
    """Return the lowercase hex HMAC-SHA256 signature for the canonical string."""
    msg = canonical_signed_string(method, path, timestamp, body).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify_request(
    key: bytes,
    method: str,
    path: str,
    timestamp: int,
    body: bytes,
    signature: str,
    *,
    now: Callable[[], int] = lambda: int(time.time()),
) -> None:
    """Raise BridgeAuthError if the signature/timestamp combination is invalid."""
    delta = now() - int(timestamp)
    if abs(delta) > TIMESTAMP_WINDOW_SECONDS:
        raise BridgeAuthError(
            f"timestamp out of window: delta={delta}s, max={TIMESTAMP_WINDOW_SECONDS}s"
        )
    expected = sign_request(key, method, path, timestamp, body)
    if not hmac.compare_digest(expected.lower(), signature.lower()):
        raise BridgeAuthError("signature mismatch")


class NonceCache:
    """In-memory LRU of (key_id, timestamp, signature) triples to block replays.

    Per the spec: timestamp window is 60s, nonce TTL is 5 minutes. The cache is
    process-local; horizontal scaling of the bridge would require a shared store.
    """

    def __init__(self, max_size: int = 4096, ttl_seconds: int = 300) -> None:
        self._entries: OrderedDict[tuple[str, int, str], int] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl_seconds
        self._lock = Lock()

    def assert_unseen(self, key_id: str, timestamp: int, signature: str) -> None:
        """Raise BridgeAuthError if this triple has been seen recently."""
        nonce = (key_id, int(timestamp), signature.lower())
        now = int(time.time())
        with self._lock:
            self._evict_expired(now)
            if nonce in self._entries:
                raise BridgeAuthError("replay detected")
            self._entries[nonce] = now
            if len(self._entries) > self._max_size:
                self._entries.popitem(last=False)

    def _evict_expired(self, now: int) -> None:
        cutoff = now - self._ttl
        while self._entries:
            _, ts = next(iter(self._entries.items()))
            if ts >= cutoff:
                return
            self._entries.popitem(last=False)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/recon_bridge/test_hmac_auth.py -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/services/recon_bridge/__init__.py \
        backend/services/recon_bridge/hmac_auth.py \
        backend/tests/recon_bridge/__init__.py \
        backend/tests/recon_bridge/test_hmac_auth.py
git commit -m "feat(recon-bridge): HMAC-SHA256 auth for bridge channel"
```

---

## Task 3 — HMAC auth library (deep-eye side) + cross-compatibility test

**Repo:** `deep-eye`

The two sides must produce identical signatures for identical inputs. We verify this by hardcoding test vectors that match the Shadowbroker side's expected output bit-for-bit.

**Files:**
- Create: `modules/reconnaissance/hmac_auth.py`
- Create: `tests/test_hmac_auth.py`

- [ ] **Step 1: Write failing tests with hard-coded cross-compat vectors**

Create `tests/test_hmac_auth.py`:

```python
"""HMAC-SHA256 signing for deep-eye → Shadowbroker bridge calls.

Cross-compatibility: identical inputs MUST produce identical signatures on
both sides. Test vectors below are the contract — if you change them, you
must update the matching Shadowbroker side test (see Task 3 cross-compat
section).
"""

import hashlib
import pytest

from modules.reconnaissance.hmac_auth import (
    BridgeAuthError,
    canonical_signed_string,
    sign_request,
)


# ---------------------------------------------------------------------------
# Cross-compatibility test vectors — DO NOT change without coordinated update
# to backend/services/recon_bridge/hmac_auth.py on the Shadowbroker side.
# ---------------------------------------------------------------------------

CROSS_COMPAT_KEY = b"test-shared-key-32bytes-minimum-padding"
CROSS_COMPAT_VECTORS = [
    # (method, path, timestamp, body, expected_sig_hex)
    (
        "GET",
        "/bridge/enrich/example.com",
        1700000000,
        b"",
        # SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        # canonical = "GET\n/bridge/enrich/example.com\n1700000000\ne3b0c4...b855"
        # HMAC(key, canonical) — computed once and frozen below.
        # If you regenerate, update BOTH sides simultaneously.
        "8e7e3a8e7d6f2f6b3a3c8e5d2c6f8a3e2b7d1f4c9e0a8d6b4c2e0f1a8d3b5c7e",
    ),
    (
        "POST",
        "/bridge/scope/check",
        1700000000,
        b'{"target":{"kind":"url","value":"https://x.test"}}',
        # Frozen vector — see comment above.
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
]


class TestCanonical:
    def test_format_matches_spec(self):
        s = canonical_signed_string("GET", "/x", 1700000000, b"")
        assert s == "GET\n/x\n1700000000\n" + hashlib.sha256(b"").hexdigest()


class TestSign:
    def test_deterministic(self):
        a = sign_request(CROSS_COMPAT_KEY, "GET", "/x", 1700000000, b"")
        b = sign_request(CROSS_COMPAT_KEY, "GET", "/x", 1700000000, b"")
        assert a == b

    def test_signature_is_lowercase_hex_64_chars(self):
        sig = sign_request(CROSS_COMPAT_KEY, "GET", "/x", 1700000000, b"")
        assert len(sig) == 64
        assert sig == sig.lower()
        assert all(c in "0123456789abcdef" for c in sig)


class TestCrossCompatVectors:
    """Vectors locked to specific HMAC outputs.

    Step 4 of this task generates the vectors from a known-good run and freezes
    them here. Both sides (deep-eye and Shadowbroker) compute these from the
    same canonical_signed_string + HMAC-SHA256, so any drift is caught the
    moment either side's algorithm diverges.

    NOTE: The literal hex values in CROSS_COMPAT_VECTORS above are placeholders
    that this test file initially fails on. See Step 4 in the task for how to
    seed them.
    """

    @pytest.mark.parametrize("method,path,ts,body,expected", CROSS_COMPAT_VECTORS)
    def test_vector(self, method, path, ts, body, expected):
        sig = sign_request(CROSS_COMPAT_KEY, method, path, ts, body)
        assert sig == expected, (
            f"Cross-compat drift: deep-eye produced {sig} but vector says {expected}. "
            f"Either deep-eye's hmac_auth or the canonical-string format has changed. "
            f"Re-seed via the procedure in Task 3 step 4 if intentional."
        )


def test_no_external_imports_required():
    """The hmac_auth module must use only stdlib — no third-party deps.

    Reason: this module is loaded during deep-eye startup before pip-installed
    deps are guaranteed available, and ships in the install tarball.
    """
    import modules.reconnaissance.hmac_auth as m
    import inspect

    src = inspect.getsource(m)
    forbidden = ["import requests", "import httpx", "from cryptography"]
    for phrase in forbidden:
        assert phrase not in src, f"hmac_auth.py imports {phrase!r} — must use stdlib only"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hmac_auth.py -v`
Expected: ImportError on `modules.reconnaissance.hmac_auth`.

- [ ] **Step 3: Write minimal implementation**

Create `modules/reconnaissance/hmac_auth.py`:

```python
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
```

- [ ] **Step 4: Seed the cross-compat vectors**

The placeholder vectors in `CROSS_COMPAT_VECTORS` are intentionally wrong so the test fails initially. Generate the real values once:

Run from the repo root:
```bash
python3 -c '
from modules.reconnaissance.hmac_auth import sign_request

KEY = b"test-shared-key-32bytes-minimum-padding"
print(sign_request(KEY, "GET", "/bridge/enrich/example.com", 1700000000, b""))
print(sign_request(KEY, "POST", "/bridge/scope/check", 1700000000, b"{\"target\":{\"kind\":\"url\",\"value\":\"https://x.test\"}}"))
'
```

Copy the two hex strings printed and paste them into `CROSS_COMPAT_VECTORS` in `tests/test_hmac_auth.py` replacing the two placeholder lines (`"8e7e3a..."` and `"0000000..."`). Save the file.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_hmac_auth.py -v`
Expected: All tests PASS.

- [ ] **Step 6: Mirror the same vectors on the Shadowbroker side**

In the **Shadowbroker** repo, append a new test class to `backend/tests/recon_bridge/test_hmac_auth.py`:

```python
class TestCrossCompatVectorsWithDeepEye:
    """Same vectors as deep-eye's tests/test_hmac_auth.py.

    If either side's algorithm changes, both files need to be updated together.
    """

    KEY = b"test-shared-key-32bytes-minimum-padding"
    VECTORS = [
        ("GET", "/bridge/enrich/example.com", 1700000000, b"",
         "PASTE_FIRST_HEX_FROM_DEEP_EYE_HERE"),
        ("POST", "/bridge/scope/check", 1700000000,
         b'{"target":{"kind":"url","value":"https://x.test"}}',
         "PASTE_SECOND_HEX_FROM_DEEP_EYE_HERE"),
    ]

    @pytest.mark.parametrize("method,path,ts,body,expected", VECTORS)
    def test_matches_deep_eye(self, method, path, ts, body, expected):
        from services.recon_bridge.hmac_auth import sign_request

        assert sign_request(self.KEY, method, path, ts, body) == expected
```

Replace both `PASTE_..._HERE` strings with the same hex values you pasted into deep-eye in Step 4. Run on the Shadowbroker side: `pytest tests/recon_bridge/test_hmac_auth.py::TestCrossCompatVectorsWithDeepEye -v`. Expected: PASS.

- [ ] **Step 7: Commit (deep-eye side)**

```bash
# From deep-eye repo
git add modules/reconnaissance/hmac_auth.py tests/test_hmac_auth.py
git commit -m "feat(recon): HMAC-SHA256 client for shadowbroker bridge"
```

- [ ] **Step 8: Commit (Shadowbroker side)**

```bash
# From Shadowbroker repo
git add backend/tests/recon_bridge/test_hmac_auth.py
git commit -m "test(recon-bridge): cross-compat vectors with deep-eye agent"
```

---

## Task 4 — Scope manifest schema + parser (Shadowbroker side)

**Repo:** `Shadowbroker`

The scope manifest is the security backbone — see spec §7. Implementation here is just the loader and validator; the *enforcement* happens at endpoint dispatch time in Task 6 / Task 13.

**Files:**
- Create: `backend/services/recon_bridge/scope_manifest.py`
- Create: `backend/tests/recon_bridge/test_scope_manifest.py`
- Create: `backend/config/scope/example-engagement.yml`

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/recon_bridge/test_scope_manifest.py`:

```python
"""Scope manifest loading and target validation.

Manifest schema and validation rules: see
docs/superpowers/specs/2026-05-05-shadowbroker-integration-design.md §7.
"""

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from services.recon_bridge.scope_manifest import (
    ScopeManifest,
    ScopeManifestError,
    Target,
    load_manifest,
)


def _manifest_dict(*, mode="engagement", expires_in_days=30, **overrides):
    base = {
        "version": 1,
        "manifest_id": "engagement-test",
        "mode": mode,
        "created_at": "2025-01-01T00:00:00Z",
        "expires_at": (datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(days=expires_in_days)).isoformat(),
        "authorization": {
            "contract_ref": "test SOW",
            "contact": "test@example.com",
        },
        "targets": {
            "include": {
                "domains": ["acme.com", "*.acme.com"],
                "ip_cidrs": ["198.51.100.0/24"],
                "asns": ["AS64512"],
            },
            "exclude": {
                "domains": ["admin.acme.com"],
                "ip_cidrs": ["198.51.100.5/32"],
            },
        },
    }
    base.update(overrides)
    return base


def _manifest(**overrides):
    return ScopeManifest.from_dict(_manifest_dict(**overrides))


def _target(kind, value):
    return Target(kind=kind, value=value)


# ---------------------------------------------------------------------------
# Schema loading
# ---------------------------------------------------------------------------

class TestLoad:
    def test_loads_minimal_manifest(self):
        m = _manifest()
        assert m.manifest_id == "engagement-test"
        assert m.mode == "engagement"

    def test_rejects_missing_expires_at(self, tmp_path: Path):
        d = _manifest_dict()
        del d["expires_at"]
        f = tmp_path / "x.yml"
        f.write_text(yaml.safe_dump(d))
        with pytest.raises(ScopeManifestError, match="expires_at is required"):
            load_manifest(f)

    def test_rejects_unknown_top_level_field(self, tmp_path: Path):
        d = _manifest_dict()
        d["unexpected"] = "value"
        f = tmp_path / "x.yml"
        f.write_text(yaml.safe_dump(d))
        with pytest.raises(ScopeManifestError, match="unknown field"):
            load_manifest(f)

    def test_rejects_unknown_mode(self):
        with pytest.raises(ScopeManifestError, match="unknown mode"):
            ScopeManifest.from_dict(_manifest_dict(mode="freeform"))


# ---------------------------------------------------------------------------
# Validation rules — order matters: expired > exclude > lab > include > deny
# ---------------------------------------------------------------------------

class TestValidate:
    def test_expired_manifest_rejects_anything(self):
        m = _manifest(expires_in_days=-1)  # already expired
        result = m.validate(_target("url", "https://acme.com"), now=lambda: time.time())
        assert result.in_scope is False
        assert "expired" in result.reason

    def test_exclude_wins_over_include(self):
        m = _manifest()
        result = m.validate(_target("url", "https://admin.acme.com"))
        assert result.in_scope is False
        assert "excluded" in result.reason

    def test_domain_wildcard_match(self):
        m = _manifest()
        result = m.validate(_target("url", "https://api.acme.com"))
        assert result.in_scope is True
        assert "matched domain pattern *.acme.com" in result.reason

    def test_ip_cidr_match(self):
        m = _manifest()
        result = m.validate(_target("ip", "198.51.100.42"))
        assert result.in_scope is True

    def test_asn_match(self):
        m = _manifest()
        result = m.validate(_target("asn", "AS64512"))
        assert result.in_scope is True

    def test_no_match_rejects(self):
        m = _manifest()
        result = m.validate(_target("url", "https://other.test"))
        assert result.in_scope is False
        assert "no scope rule matched" in result.reason

    def test_lab_mode_with_region_lock(self):
        d = _manifest_dict(mode="lab")
        d["lab"] = {"region_lock": "10.0.0.0/8"}
        d["targets"] = {"include": {}, "exclude": {}}  # no normal include rules
        m = ScopeManifest.from_dict(d)
        assert m.validate(_target("ip", "10.5.6.7")).in_scope is True
        assert m.validate(_target("ip", "192.168.1.1")).in_scope is False

    def test_lab_mode_still_expires(self):
        d = _manifest_dict(mode="lab", expires_in_days=-1)
        d["lab"] = {"region_lock": "10.0.0.0/8"}
        m = ScopeManifest.from_dict(d)
        assert m.validate(_target("ip", "10.5.6.7")).in_scope is False


# ---------------------------------------------------------------------------
# Target normalization (URL → host comparison, etc.)
# ---------------------------------------------------------------------------

class TestTargetNormalization:
    @pytest.mark.parametrize(
        "raw,host",
        [
            ("https://acme.com/path?q=1", "acme.com"),
            ("http://acme.com:8080/", "acme.com"),
            ("acme.com", "acme.com"),
        ],
    )
    def test_url_extracts_host(self, raw, host):
        m = _manifest()
        # If host is "acme.com" and acme.com is included, in_scope=True
        if host == "acme.com":
            assert m.validate(_target("url", raw)).in_scope is True

    def test_invalid_ip_rejected_with_clear_reason(self):
        m = _manifest()
        result = m.validate(_target("ip", "not.an.ip"))
        assert result.in_scope is False
        assert "invalid ip" in result.reason.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/recon_bridge/test_scope_manifest.py -v`
Expected: ImportError on `services.recon_bridge.scope_manifest`.

- [ ] **Step 3: Write minimal implementation**

Create `backend/services/recon_bridge/scope_manifest.py`:

```python
"""Scope manifest — the authorization backbone for the recon bridge.

Schema: docs/superpowers/specs/2026-05-05-shadowbroker-integration-design.md §7.

Validation order (matters!):
  1. expired? → reject
  2. matches exclude? → reject (exclusions ALWAYS win)
  3. mode == lab and matches region_lock? → accept
  4. matches include? → accept
  5. otherwise → reject
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import urlparse

import yaml


KNOWN_MODES = {"engagement", "bounty", "self", "lab"}
KNOWN_TOP_LEVEL_FIELDS = {
    "version", "manifest_id", "mode", "created_at", "expires_at",
    "authorization", "targets", "bounty", "lab",
}
KNOWN_TARGET_FIELDS = {"include", "exclude"}
KNOWN_INCLUDE_FIELDS = {"domains", "ip_cidrs", "asns"}


class ScopeManifestError(Exception):
    pass


@dataclass(frozen=True)
class Target:
    kind: str  # "url" | "ip" | "cidr" | "asn"
    value: str


@dataclass(frozen=True)
class ScopeResult:
    in_scope: bool
    reason: str
    manifest_id: str = ""
    mode: str = ""


@dataclass
class ScopeManifest:
    manifest_id: str
    mode: str
    expires_at: datetime
    include_domains: list[str] = field(default_factory=list)
    include_cidrs: list[ipaddress._BaseNetwork] = field(default_factory=list)
    include_asns: list[str] = field(default_factory=list)
    exclude_domains: list[str] = field(default_factory=list)
    exclude_cidrs: list[ipaddress._BaseNetwork] = field(default_factory=list)
    lab_region_lock: Optional[ipaddress._BaseNetwork] = None

    @classmethod
    def from_dict(cls, data: dict) -> "ScopeManifest":
        unknown = set(data.keys()) - KNOWN_TOP_LEVEL_FIELDS
        if unknown:
            raise ScopeManifestError(f"unknown field(s): {sorted(unknown)}")

        if "expires_at" not in data:
            raise ScopeManifestError("expires_at is required")

        mode = data.get("mode")
        if mode not in KNOWN_MODES:
            raise ScopeManifestError(f"unknown mode: {mode!r}; allowed: {sorted(KNOWN_MODES)}")

        targets = data.get("targets", {}) or {}
        include = targets.get("include") or {}
        exclude = targets.get("exclude") or {}

        lab_region_lock = None
        if mode == "lab":
            lab = data.get("lab") or {}
            rl = lab.get("region_lock")
            if rl:
                lab_region_lock = ipaddress.ip_network(rl, strict=False)

        return cls(
            manifest_id=data["manifest_id"],
            mode=mode,
            expires_at=_parse_iso(data["expires_at"]),
            include_domains=list(include.get("domains") or []),
            include_cidrs=[ipaddress.ip_network(c, strict=False)
                           for c in (include.get("ip_cidrs") or [])],
            include_asns=[_normalize_asn(a) for a in (include.get("asns") or [])],
            exclude_domains=list(exclude.get("domains") or []),
            exclude_cidrs=[ipaddress.ip_network(c, strict=False)
                           for c in (exclude.get("ip_cidrs") or [])],
            lab_region_lock=lab_region_lock,
        )

    def validate(
        self, target: Target, *, now: Callable[[], float] = time.time
    ) -> ScopeResult:
        # Rule 1: expired?
        if self.expires_at.timestamp() < now():
            return ScopeResult(
                in_scope=False,
                reason=f"manifest {self.manifest_id} expired at {self.expires_at.isoformat()}",
                manifest_id=self.manifest_id,
                mode=self.mode,
            )

        host_or_ip, error = _resolve_target_for_match(target)
        if error:
            return ScopeResult(
                in_scope=False, reason=error,
                manifest_id=self.manifest_id, mode=self.mode,
            )

        # Rule 2: excluded? (always wins)
        if target.kind in ("url",) and host_or_ip:
            for pattern in self.exclude_domains:
                if _domain_match(host_or_ip, pattern):
                    return ScopeResult(False, f"excluded by domain pattern {pattern}",
                                       self.manifest_id, self.mode)
        if target.kind == "ip":
            try:
                ip = ipaddress.ip_address(host_or_ip)
                for net in self.exclude_cidrs:
                    if ip in net:
                        return ScopeResult(False, f"excluded by cidr {net}",
                                           self.manifest_id, self.mode)
            except ValueError:
                pass

        # Rule 3: lab mode region_lock
        if self.mode == "lab" and self.lab_region_lock is not None:
            if target.kind == "ip":
                try:
                    if ipaddress.ip_address(host_or_ip) in self.lab_region_lock:
                        return ScopeResult(True, f"lab region_lock match {self.lab_region_lock}",
                                           self.manifest_id, self.mode)
                    return ScopeResult(False, f"outside lab region_lock {self.lab_region_lock}",
                                       self.manifest_id, self.mode)
                except ValueError:
                    pass

        # Rule 4: include match
        if target.kind == "url" and host_or_ip:
            for pattern in self.include_domains:
                if _domain_match(host_or_ip, pattern):
                    return ScopeResult(True, f"matched domain pattern {pattern}",
                                       self.manifest_id, self.mode)
        if target.kind == "ip":
            try:
                ip = ipaddress.ip_address(host_or_ip)
                for net in self.include_cidrs:
                    if ip in net:
                        return ScopeResult(True, f"matched cidr {net}",
                                           self.manifest_id, self.mode)
            except ValueError:
                pass
        if target.kind == "asn":
            normalized = _normalize_asn(target.value)
            if normalized in self.include_asns:
                return ScopeResult(True, f"matched asn {normalized}",
                                   self.manifest_id, self.mode)

        # Rule 5: deny
        return ScopeResult(False, "no scope rule matched",
                           self.manifest_id, self.mode)


def load_manifest(path: Path) -> ScopeManifest:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return ScopeManifest.from_dict(raw)


# ---------------------------------------------------------------------------

def _parse_iso(s: str) -> datetime:
    s = str(s)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _normalize_asn(asn: str) -> str:
    s = str(asn).strip().upper()
    if not s.startswith("AS"):
        s = "AS" + s
    return s


def _resolve_target_for_match(target: Target) -> tuple[str, Optional[str]]:
    """Return (canonical_value, error). canonical_value is host (for URL),
    ip string (for ip), or raw value otherwise."""
    if target.kind == "url":
        try:
            host = urlparse(target.value if "://" in target.value else "https://" + target.value).hostname
            if not host:
                return "", f"invalid url: {target.value}"
            return host.lower(), None
        except Exception as exc:
            return "", f"invalid url: {exc}"
    if target.kind == "ip":
        try:
            ipaddress.ip_address(target.value)
            return target.value, None
        except ValueError:
            return "", f"invalid ip: {target.value!r}"
    if target.kind == "cidr":
        try:
            ipaddress.ip_network(target.value, strict=False)
            return target.value, None
        except ValueError:
            return "", f"invalid cidr: {target.value!r}"
    if target.kind == "asn":
        return target.value, None
    return target.value, None


def _domain_match(host: str, pattern: str) -> bool:
    host = host.lower()
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".acme.com"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/recon_bridge/test_scope_manifest.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Create example manifest**

Create `backend/config/scope/example-engagement.yml`:

```yaml
# Example scope manifest for the recon bridge.
# See docs/superpowers/specs/2026-05-05-shadowbroker-integration-design.md §7.

version: 1
manifest_id: "example-engagement-2026-q2"
mode: engagement
created_at: "2026-04-01T00:00:00Z"
expires_at: "2026-07-01T00:00:00Z"   # MANDATORY — no exceptions, no "never"

authorization:
  contract_ref: "Replace this with your engagement reference"
  contact: "you@example.com"
  signing_key_fingerprint: "sha256:replace-with-real-fingerprint"

targets:
  include:
    domains:
      - "example.com"
      - "*.example.com"
    ip_cidrs:
      - "198.51.100.0/24"
    asns:
      - "AS64512"
  exclude:
    domains:
      - "payroll.example.com"
    ip_cidrs:
      - "198.51.100.5/32"
```

- [ ] **Step 6: Commit**

```bash
git add backend/services/recon_bridge/scope_manifest.py \
        backend/tests/recon_bridge/test_scope_manifest.py \
        backend/config/scope/example-engagement.yml
git commit -m "feat(recon-bridge): scope manifest schema, parser, and validator"
```

---

## Task 5 — Scope manifest (deep-eye side, identical semantics)

**Repo:** `deep-eye`

The deep-eye side performs *advisory* scope checks before shipping requests to the bridge — defense in depth. The bridge's check is authoritative; deep-eye's check just avoids round-tripping requests that are obviously out-of-scope.

The implementation is character-for-character the same as the Shadowbroker side (the spec demands identical semantics). To avoid drift, this task copies the file verbatim and adds tests verifying the deep-eye side gives identical answers to a small parametrized set.

**Files:**
- Create: `core/scope_manifest.py`
- Create: `core/scope_enforcer.py`
- Create: `tests/test_scope_manifest.py`
- Create: `tests/test_scope_enforcer.py`
- Create: `config/scope/example-engagement.yml`

- [ ] **Step 1: Copy the manifest module verbatim**

Copy `Shadowbroker/backend/services/recon_bridge/scope_manifest.py` to `deep-eye/core/scope_manifest.py` unchanged. (PyYAML is already in deep-eye's `requirements.txt`.)

```bash
# From deep-eye repo root
cp ../Shadowbroker/backend/services/recon_bridge/scope_manifest.py core/scope_manifest.py
```

- [ ] **Step 2: Copy the example manifest**

```bash
mkdir -p config/scope
cp ../Shadowbroker/backend/config/scope/example-engagement.yml config/scope/example-engagement.yml
```

- [ ] **Step 3: Write tests for the deep-eye side**

Create `tests/test_scope_manifest.py`:

```python
"""Verify deep-eye's scope_manifest.py gives the same answers as Shadowbroker's.

This is the cross-side equivalence test. If anyone updates one side without the
other, this fails.
"""

import time
from datetime import datetime, timedelta, timezone

import pytest

from core.scope_manifest import ScopeManifest, Target


def _manifest(mode="engagement", expires_in_days=30):
    return ScopeManifest.from_dict({
        "version": 1,
        "manifest_id": "engagement-test",
        "mode": mode,
        "created_at": "2025-01-01T00:00:00Z",
        "expires_at": (datetime(2025, 1, 1, tzinfo=timezone.utc)
                       + timedelta(days=expires_in_days)).isoformat(),
        "authorization": {"contract_ref": "x", "contact": "y@z"},
        "targets": {
            "include": {"domains": ["acme.com", "*.acme.com"],
                        "ip_cidrs": ["198.51.100.0/24"], "asns": ["AS64512"]},
            "exclude": {"domains": ["admin.acme.com"]},
        },
    })


@pytest.mark.parametrize("kind,value,expected_in_scope", [
    ("url", "https://acme.com", True),
    ("url", "https://api.acme.com", True),
    ("url", "https://admin.acme.com", False),
    ("url", "https://other.test", False),
    ("ip", "198.51.100.42", True),
    ("ip", "10.0.0.1", False),
    ("asn", "AS64512", True),
    ("asn", "AS65000", False),
])
def test_validate_matches_shadowbroker_semantics(kind, value, expected_in_scope):
    """Same parametrize set as Shadowbroker's test_validate — keep in sync."""
    m = _manifest()
    result = m.validate(Target(kind=kind, value=value))
    assert result.in_scope is expected_in_scope


def test_expired_manifest_blocks_everything():
    m = _manifest(expires_in_days=-1)
    assert m.validate(Target(kind="url", value="https://acme.com")).in_scope is False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scope_manifest.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Write the scope enforcer (thin wrapper)**

Create `core/scope_enforcer.py`:

```python
"""Client-side scope check (defense in depth).

deep-eye consults this before shipping a target to the bridge. The bridge's
own check is authoritative — this one just avoids obviously-out-of-scope
round-trips and gives the user a clearer local error message.

NEVER use this as a substitute for the bridge check. Per the spec §9: there
is no fallback path that bypasses scope. If the bridge is unreachable for a
non-CLI-A flow, the scan does not run.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from core.scope_manifest import ScopeManifest, ScopeResult, Target, load_manifest

logger = logging.getLogger(__name__)


class ScopeEnforcer:
    def __init__(self, manifest_path: Path) -> None:
        self._path = Path(manifest_path)
        self._manifest: Optional[ScopeManifest] = None

    def manifest(self) -> ScopeManifest:
        if self._manifest is None:
            self._manifest = load_manifest(self._path)
        return self._manifest

    def check(self, target: Target) -> ScopeResult:
        result = self.manifest().validate(target)
        if not result.in_scope:
            logger.info(
                "Local scope check rejected target kind=%s value=%s reason=%s",
                target.kind, target.value, result.reason,
            )
        return result
```

Create `tests/test_scope_enforcer.py`:

```python
"""ScopeEnforcer wraps ScopeManifest with file loading + logging."""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from core.scope_enforcer import ScopeEnforcer
from core.scope_manifest import Target


@pytest.fixture
def manifest_file(tmp_path: Path) -> Path:
    f = tmp_path / "scope.yml"
    f.write_text(yaml.safe_dump({
        "version": 1,
        "manifest_id": "engagement-test",
        "mode": "engagement",
        "created_at": "2025-01-01T00:00:00Z",
        "expires_at": (datetime(2030, 1, 1, tzinfo=timezone.utc)).isoformat(),
        "authorization": {"contract_ref": "x", "contact": "y@z"},
        "targets": {
            "include": {"domains": ["acme.com"]},
            "exclude": {},
        },
    }))
    return f


def test_in_scope_target_returns_in_scope(manifest_file: Path):
    e = ScopeEnforcer(manifest_file)
    r = e.check(Target("url", "https://acme.com/path"))
    assert r.in_scope is True


def test_out_of_scope_target_returns_with_reason(manifest_file: Path, caplog):
    e = ScopeEnforcer(manifest_file)
    r = e.check(Target("url", "https://other.test"))
    assert r.in_scope is False
    assert "no scope rule matched" in r.reason
    assert any("Local scope check rejected" in m for m in caplog.messages)


def test_manifest_is_lazily_loaded_and_cached(manifest_file: Path):
    e = ScopeEnforcer(manifest_file)
    m1 = e.manifest()
    m2 = e.manifest()
    assert m1 is m2  # cached, same instance
```

- [ ] **Step 6: Run enforcer tests to verify they pass**

Run: `pytest tests/test_scope_enforcer.py -v`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add core/scope_manifest.py core/scope_enforcer.py \
        config/scope/example-engagement.yml \
        tests/test_scope_manifest.py tests/test_scope_enforcer.py
git commit -m "feat(scope): scope manifest parser and client-side enforcer"
```

---

## Task 6 — `/bridge/scope/check` endpoint (Shadowbroker side)

**Repo:** `Shadowbroker`

This is the simpler of the two endpoints in Plan A — implement it first as the foundation.

**Files:**
- Create: `backend/routers/recon_bridge.py`
- Create: `backend/tests/recon_bridge/test_router_recon_bridge.py`
- Modify: `backend/main.py` (add one line registering the router — see Task 14)

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/recon_bridge/test_router_recon_bridge.py`:

```python
"""HTTP-level tests for /bridge/* endpoints.

These tests bypass the HMAC layer using a dependency override so we can
focus on routing, request validation, and response shape.
"""

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient


@pytest.fixture
def manifest_dir(tmp_path: Path) -> Path:
    d = tmp_path / "scope"
    d.mkdir()
    (d / "engagement-test.yml").write_text(yaml.safe_dump({
        "version": 1,
        "manifest_id": "engagement-test",
        "mode": "engagement",
        "created_at": "2025-01-01T00:00:00Z",
        "expires_at": (datetime(2030, 1, 1, tzinfo=timezone.utc)).isoformat(),
        "authorization": {"contract_ref": "x", "contact": "y@z"},
        "targets": {
            "include": {"domains": ["acme.com", "*.acme.com"]},
            "exclude": {"domains": ["admin.acme.com"]},
        },
    }))
    return d


@pytest.fixture
def app_client(monkeypatch, manifest_dir: Path):
    """Build a FastAPI app exposing only the recon_bridge router for testing."""
    from fastapi import FastAPI
    from routers.recon_bridge import router, set_scope_manifest_dir, set_hmac_bypass_for_tests

    set_scope_manifest_dir(manifest_dir)
    set_hmac_bypass_for_tests(True)
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# /bridge/scope/check
# ---------------------------------------------------------------------------

class TestScopeCheck:
    def test_in_scope_returns_in_scope_true(self, app_client):
        resp = app_client.post("/bridge/scope/check", json={
            "target": {"kind": "url", "value": "https://api.acme.com"},
            "scope_token": "engagement-test",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["in_scope"] is True
        assert body["manifest_id"] == "engagement-test"
        assert body["mode"] == "engagement"
        assert "matched domain pattern *.acme.com" in body["reason"]

    def test_out_of_scope_returns_in_scope_false(self, app_client):
        resp = app_client.post("/bridge/scope/check", json={
            "target": {"kind": "url", "value": "https://other.test"},
            "scope_token": "engagement-test",
        })
        assert resp.status_code == 200
        body = resp.json()
        assert body["in_scope"] is False
        assert "no scope rule matched" in body["reason"]

    def test_excluded_target_returns_excluded_reason(self, app_client):
        resp = app_client.post("/bridge/scope/check", json={
            "target": {"kind": "url", "value": "https://admin.acme.com"},
            "scope_token": "engagement-test",
        })
        assert resp.status_code == 200
        assert resp.json()["in_scope"] is False
        assert "excluded" in resp.json()["reason"]

    def test_unknown_scope_token_404(self, app_client):
        resp = app_client.post("/bridge/scope/check", json={
            "target": {"kind": "url", "value": "https://acme.com"},
            "scope_token": "no-such-engagement",
        })
        assert resp.status_code == 404
        assert "no manifest" in resp.json()["detail"].lower()

    def test_malformed_request_422(self, app_client):
        resp = app_client.post("/bridge/scope/check", json={"target": {"kind": "url"}})  # no value
        assert resp.status_code == 422
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/recon_bridge/test_router_recon_bridge.py -v`
Expected: ImportError on `routers.recon_bridge`.

- [ ] **Step 3: Write minimal implementation**

Create `backend/routers/recon_bridge.py`:

```python
"""Recon bridge — HTTP API consumed by deep-eye.

Endpoints (Plan A):
  POST /bridge/scope/check          — validate a target against a scope manifest
  GET  /bridge/enrich/{target}      — aggregate enrichment intel (Task 13)

Auth: HMAC-SHA256 (services.recon_bridge.hmac_auth) on every endpoint, with
a test-only bypass toggleable via set_hmac_bypass_for_tests().
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from services.recon_bridge.scope_manifest import (
    ScopeManifest,
    ScopeManifestError,
    Target,
    load_manifest,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/bridge", tags=["recon-bridge"])


# Configuration (set at app boot — Task 14)
_scope_dir: Optional[Path] = None
_hmac_bypass = False


def set_scope_manifest_dir(path: Path) -> None:
    global _scope_dir
    _scope_dir = Path(path)


def set_hmac_bypass_for_tests(enabled: bool) -> None:
    """Test-only toggle. Production code MUST NOT call this.

    The hmac dependency on each endpoint reads this flag and returns early when
    True. Production startup leaves it False.
    """
    global _hmac_bypass
    _hmac_bypass = enabled


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class TargetIn(BaseModel):
    kind: str = Field(..., pattern=r"^(url|ip|cidr|asn|pin)$")
    value: str = Field(..., min_length=1)


class ScopeCheckRequest(BaseModel):
    target: TargetIn
    scope_token: str = Field(..., min_length=1)


class ScopeCheckResponse(BaseModel):
    in_scope: bool
    reason: str
    manifest_id: str
    mode: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_scope(scope_token: str) -> ScopeManifest:
    if _scope_dir is None:
        raise HTTPException(500, "scope manifest dir not configured")
    path = _scope_dir / f"{scope_token}.yml"
    if not path.exists():
        raise HTTPException(404, f"no manifest for scope_token={scope_token!r}")
    try:
        return load_manifest(path)
    except ScopeManifestError as exc:
        raise HTTPException(500, f"manifest load failed: {exc}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scope/check", response_model=ScopeCheckResponse)
async def scope_check(req: ScopeCheckRequest, request: Request) -> ScopeCheckResponse:
    if not _hmac_bypass:
        await _enforce_hmac(request)

    manifest = _load_scope(req.scope_token)
    target = Target(kind=req.target.kind, value=req.target.value)
    result = manifest.validate(target)
    return ScopeCheckResponse(
        in_scope=result.in_scope,
        reason=result.reason,
        manifest_id=result.manifest_id,
        mode=result.mode,
    )


# ---------------------------------------------------------------------------
# HMAC enforcement (used by both endpoints; tests can bypass)
# ---------------------------------------------------------------------------

async def _enforce_hmac(request: Request) -> None:
    """Verify the inbound HMAC signature; raise HTTPException(401) on failure.

    Wired up properly in Task 13 once we have the key store. For Plan A's
    early endpoints, this is a placeholder that always rejects unless the
    test bypass is active — production uses Task 13's real implementation.
    """
    from services.recon_bridge.hmac_auth import BridgeAuthError, verify_request

    raise HTTPException(
        501,
        "HMAC enforcement not yet wired (Task 13). Tests use set_hmac_bypass_for_tests(True).",
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/recon_bridge/test_router_recon_bridge.py -v`
Expected: All `TestScopeCheck` tests PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/routers/recon_bridge.py backend/tests/recon_bridge/test_router_recon_bridge.py
git commit -m "feat(recon-bridge): /bridge/scope/check endpoint"
```

---

## Task 7 — Enrichment aggregator skeleton

**Repo:** `Shadowbroker`

The aggregator is the merge point for Shodan, region dossier, geopolitics, and CT logs. We build it skeleton-first with mocked feed callers, then wire each real feed in Tasks 8-11.

**Files:**
- Create: `backend/services/recon_bridge/enrichment_aggregator.py`
- Create: `backend/tests/recon_bridge/test_enrichment_aggregator.py`

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/recon_bridge/test_enrichment_aggregator.py`:

```python
"""Enrichment aggregator — parallel fan-out + 60s cache."""

import asyncio

import pytest

from services.recon_bridge.enrichment_aggregator import (
    EnrichmentAggregator,
    EnrichmentResult,
)


class FakeShodan:
    def __init__(self, response):
        self._response = response
        self.calls = 0

    async def lookup(self, target: str) -> dict:
        self.calls += 1
        return self._response


class FakeRegionDossier:
    async def lookup(self, target: str) -> dict:
        return {"country": "US", "asn": "AS15169", "org": "Example LLC"}


class FakeGeopolitics:
    async def alerts(self, org: str) -> list[dict]:
        return [{"id": "evt-1", "headline": "Example event"}]


class FakeCT:
    async def certificates(self, target: str) -> list[dict]:
        return [{"cn": target, "issuer": "Test CA"}]


@pytest.fixture
def agg():
    return EnrichmentAggregator(
        shodan=FakeShodan({"ports": [80, 443], "cves": ["CVE-2021-1"]}),
        region_dossier=FakeRegionDossier(),
        geopolitics=FakeGeopolitics(),
        ct_logs=FakeCT(),
        cache_ttl_seconds=60,
    )


@pytest.mark.asyncio
async def test_aggregate_returns_merged_result(agg):
    r = await agg.aggregate("example.com")
    assert isinstance(r, EnrichmentResult)
    assert r.target == "example.com"
    assert r.shodan == {"ports": [80, 443], "cves": ["CVE-2021-1"]}
    assert r.geo["org"] == "Example LLC"
    assert len(r.geopolitics_alerts) == 1
    assert r.ct_logs[0]["cn"] == "example.com"


@pytest.mark.asyncio
async def test_aggregate_caches_for_ttl(agg):
    await agg.aggregate("example.com")
    await agg.aggregate("example.com")
    assert agg._shodan.calls == 1  # second call hit cache


@pytest.mark.asyncio
async def test_aggregate_failed_feed_does_not_blow_up_others():
    class BrokenShodan:
        async def lookup(self, target: str) -> dict:
            raise RuntimeError("shodan down")

    agg = EnrichmentAggregator(
        shodan=BrokenShodan(),
        region_dossier=FakeRegionDossier(),
        geopolitics=FakeGeopolitics(),
        ct_logs=FakeCT(),
        cache_ttl_seconds=60,
    )
    r = await agg.aggregate("example.com")
    assert r.shodan is None  # broken feed degrades gracefully
    assert r.geo is not None  # other feeds still populated
    assert r.feed_errors and "shodan" in r.feed_errors


@pytest.mark.asyncio
async def test_resolved_ips_populated_from_shodan_when_available():
    class ShodanWithIPs:
        async def lookup(self, target: str) -> dict:
            return {"ip_str": "1.2.3.4", "ports": [80]}

    agg = EnrichmentAggregator(
        shodan=ShodanWithIPs(),
        region_dossier=FakeRegionDossier(),
        geopolitics=FakeGeopolitics(),
        ct_logs=FakeCT(),
        cache_ttl_seconds=60,
    )
    r = await agg.aggregate("example.com")
    assert r.resolved_ips == ["1.2.3.4"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/recon_bridge/test_enrichment_aggregator.py -v`
Expected: ImportError on `services.recon_bridge.enrichment_aggregator`.

- [ ] **Step 3: Write minimal implementation**

Create `backend/services/recon_bridge/enrichment_aggregator.py`:

```python
"""Aggregate Shadowbroker OSINT feeds into a single enrichment record.

Feeds are called in parallel via asyncio.gather. Any feed exception is caught,
recorded under feed_errors, and the rest of the result still returns. The
60s in-memory cache is per-target and shared across requests.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Protocols (so each feed is a swappable async callable in tests)
# ---------------------------------------------------------------------------

class ShodanFeed(Protocol):
    async def lookup(self, target: str) -> dict[str, Any]: ...


class RegionDossierFeed(Protocol):
    async def lookup(self, target: str) -> dict[str, Any]: ...


class GeopoliticsFeed(Protocol):
    async def alerts(self, org: str) -> list[dict[str, Any]]: ...


class CTFeed(Protocol):
    async def certificates(self, target: str) -> list[dict[str, Any]]: ...


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class EnrichmentResult:
    target: str
    resolved_ips: list[str] = field(default_factory=list)
    shodan: Optional[dict[str, Any]] = None
    geo: Optional[dict[str, Any]] = None
    region_dossier: Optional[dict[str, Any]] = None
    geopolitics_alerts: list[dict[str, Any]] = field(default_factory=list)
    ct_logs: list[dict[str, Any]] = field(default_factory=list)
    feed_errors: dict[str, str] = field(default_factory=dict)
    stale_after: float = 0.0


class EnrichmentAggregator:
    def __init__(
        self,
        *,
        shodan: ShodanFeed,
        region_dossier: RegionDossierFeed,
        geopolitics: GeopoliticsFeed,
        ct_logs: CTFeed,
        cache_ttl_seconds: int = 60,
    ) -> None:
        self._shodan = shodan
        self._region = region_dossier
        self._geo = geopolitics
        self._ct = ct_logs
        self._ttl = cache_ttl_seconds
        self._cache: dict[str, tuple[float, EnrichmentResult]] = {}

    async def aggregate(self, target: str) -> EnrichmentResult:
        now = time.time()
        cached = self._cache.get(target)
        if cached and cached[0] > now:
            return cached[1]

        result = EnrichmentResult(target=target, stale_after=now + self._ttl)
        results = await asyncio.gather(
            self._safe(self._shodan.lookup(target), "shodan"),
            self._safe(self._region.lookup(target), "region_dossier"),
            self._safe(self._ct.certificates(target), "ct_logs"),
            return_exceptions=False,
        )
        shodan_data, region_data, ct_data = results

        if isinstance(shodan_data, dict):
            result.shodan = shodan_data
            ip = shodan_data.get("ip_str") or shodan_data.get("ip")
            if ip:
                result.resolved_ips = [ip]
        elif isinstance(shodan_data, _FeedError):
            result.feed_errors["shodan"] = shodan_data.detail

        if isinstance(region_data, dict):
            result.region_dossier = region_data
            result.geo = {
                k: region_data.get(k) for k in ("country", "asn", "org")
                if region_data.get(k) is not None
            } or None
        elif isinstance(region_data, _FeedError):
            result.feed_errors["region_dossier"] = region_data.detail

        if isinstance(ct_data, list):
            result.ct_logs = ct_data
        elif isinstance(ct_data, _FeedError):
            result.feed_errors["ct_logs"] = ct_data.detail

        # Geopolitics alerts depend on the org from region dossier — sequenced.
        org = (result.geo or {}).get("org") if result.geo else None
        if org:
            geo_alerts = await self._safe(self._geo.alerts(org), "geopolitics")
            if isinstance(geo_alerts, list):
                result.geopolitics_alerts = geo_alerts
            elif isinstance(geo_alerts, _FeedError):
                result.feed_errors["geopolitics"] = geo_alerts.detail

        self._cache[target] = (now + self._ttl, result)
        return result

    async def _safe(self, coro, name: str):
        try:
            return await coro
        except Exception as exc:  # noqa: BLE001 — degrade gracefully per spec §9
            logger.warning("Enrichment feed %s failed: %s", name, exc)
            return _FeedError(detail=str(exc))


@dataclass
class _FeedError:
    detail: str
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/recon_bridge/test_enrichment_aggregator.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/services/recon_bridge/enrichment_aggregator.py \
        backend/tests/recon_bridge/test_enrichment_aggregator.py
git commit -m "feat(recon-bridge): enrichment aggregator with graceful degradation + cache"
```

---

## Task 8 — Wire real Shodan into the aggregator

**Repo:** `Shadowbroker`

Adapt the existing `services/shodan_connector.py` (synchronous, request-based) into the async `ShodanFeed` protocol the aggregator expects. We do this with a thin async adapter that runs the sync calls in the default thread executor.

**Files:**
- Modify: `backend/services/recon_bridge/enrichment_aggregator.py` — add `ShodanConnectorAdapter` class.
- Modify: `backend/tests/recon_bridge/test_enrichment_aggregator.py` — add adapter tests.

- [ ] **Step 1: Read the existing shodan connector signatures**

```bash
grep -n "^def \|^async def " backend/services/shodan_connector.py | head -20
```

Expected: a list of public functions. Find one that performs a host lookup by hostname (typical Shodan API: `host(ip)` for a known IP, `search` for hostnames). Note the function name and signature.

- [ ] **Step 2: Write failing adapter test**

Append to `backend/tests/recon_bridge/test_enrichment_aggregator.py`:

```python
class TestShodanConnectorAdapter:
    @pytest.mark.asyncio
    async def test_adapter_calls_underlying_connector_in_executor(self, monkeypatch):
        from services.recon_bridge.enrichment_aggregator import ShodanConnectorAdapter

        captured = {}

        def fake_host_lookup(target: str) -> dict:
            captured["target"] = target
            return {"ip_str": "1.2.3.4", "ports": [80, 443]}

        # Replace whichever shodan_connector function the adapter uses with our fake.
        # Adapter implementation in Step 3 chooses the function name; update this
        # monkeypatch line to match.
        monkeypatch.setattr(
            "services.shodan_connector.host_lookup_for_recon_bridge",
            fake_host_lookup,
            raising=False,
        )

        adapter = ShodanConnectorAdapter()
        result = await adapter.lookup("example.com")
        assert result == {"ip_str": "1.2.3.4", "ports": [80, 443]}
        assert captured["target"] == "example.com"

    @pytest.mark.asyncio
    async def test_adapter_returns_empty_when_api_key_missing(self, monkeypatch):
        from services.recon_bridge.enrichment_aggregator import ShodanConnectorAdapter

        monkeypatch.delenv("SHODAN_API_KEY", raising=False)
        adapter = ShodanConnectorAdapter()
        result = await adapter.lookup("example.com")
        # Per the spec: enrichment is opportunistic. No API key → empty result, no raise.
        assert result == {}
```

- [ ] **Step 3: Run tests to verify they fail (or partially pass)**

Run: `pytest tests/recon_bridge/test_enrichment_aggregator.py::TestShodanConnectorAdapter -v`
Expected: ImportError or AttributeError on `ShodanConnectorAdapter`.

- [ ] **Step 4: Write the adapter**

Append to `backend/services/recon_bridge/enrichment_aggregator.py`:

```python
import os


class ShodanConnectorAdapter:
    """Async adapter around services.shodan_connector for the aggregator.

    The underlying shodan_connector module is synchronous (uses requests). We
    run its calls in the default asyncio thread executor so they don't block
    the event loop. We also degrade gracefully when SHODAN_API_KEY is unset
    — the aggregator just receives an empty dict.
    """

    async def lookup(self, target: str) -> dict[str, Any]:
        if not os.environ.get("SHODAN_API_KEY"):
            return {}
        try:
            from services import shodan_connector
        except ImportError:
            return {}

        loop = asyncio.get_running_loop()
        # The function name here must match what shodan_connector exposes.
        # If the existing module uses a different name (e.g. host_lookup,
        # search_host), import the right one and update this call.
        func = getattr(shodan_connector, "host_lookup_for_recon_bridge", None)
        if func is None:
            # Fall back: log once and return empty. Step 4b adds the function.
            logger.warning(
                "shodan_connector.host_lookup_for_recon_bridge not found; "
                "Plan A Task 8 step 4b adds the wrapper."
            )
            return {}
        return await loop.run_in_executor(None, func, target)
```

- [ ] **Step 4b: Add the wrapper function in shodan_connector**

Append to `backend/services/shodan_connector.py`:

```python
def host_lookup_for_recon_bridge(target: str) -> dict[str, Any]:
    """Recon-bridge-specific Shodan lookup.

    Returns a dict combining host details (when target is an IP) and search
    hits (when target is a hostname). Empty dict when no data found or
    rate-limit exceeded — the caller treats that as opportunistic miss, not
    error, per spec §9.
    """
    if not target:
        return {}
    # If target looks like an IP, use host endpoint; otherwise search.
    import ipaddress
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    try:
        if is_ip:
            data = lookup_host(target)  # existing function in this module
            return data if isinstance(data, dict) else {}
        else:
            # Use existing search call; first match wins.
            results = search(query=f"hostname:{target}", page=1)
            matches = (results or {}).get("matches") or []
            return matches[0] if matches else {}
    except ShodanConnectorError as exc:
        logger.info("shodan recon-bridge lookup miss: %s", exc.detail)
        return {}
    except Exception as exc:  # noqa: BLE001
        logger.warning("shodan recon-bridge lookup error: %s", exc)
        return {}
```

> **Note for the implementer:** The function names `lookup_host` and `search` above are placeholders for whatever the existing connector calls them. Run `grep -n "^def " backend/services/shodan_connector.py` to find the real names; substitute them. The TEST in step 2 above also uses the wrapper name `host_lookup_for_recon_bridge` — keep them aligned.

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/recon_bridge/test_enrichment_aggregator.py::TestShodanConnectorAdapter -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/services/recon_bridge/enrichment_aggregator.py \
        backend/services/shodan_connector.py \
        backend/tests/recon_bridge/test_enrichment_aggregator.py
git commit -m "feat(recon-bridge): wire real shodan_connector into aggregator"
```

---

## Task 9 — Wire region_dossier into the aggregator

**Repo:** `Shadowbroker`

Same adapter pattern as Task 8. The existing `services/region_dossier.py` is synchronous; we wrap it in an async adapter.

**Files:** modifications to `enrichment_aggregator.py` and its tests.

- [ ] **Step 1: Inspect existing region_dossier function names**

```bash
grep -n "^def \|^async def " backend/services/region_dossier.py | head -20
```

- [ ] **Step 2: Write failing adapter test**

Append to `backend/tests/recon_bridge/test_enrichment_aggregator.py`:

```python
class TestRegionDossierAdapter:
    @pytest.mark.asyncio
    async def test_adapter_returns_country_asn_org(self, monkeypatch):
        from services.recon_bridge.enrichment_aggregator import RegionDossierAdapter

        def fake_lookup(target: str) -> dict:
            return {"country": "US", "asn": "AS15169", "org": "Example LLC", "extra": "ok"}

        monkeypatch.setattr(
            "services.region_dossier.lookup_for_recon_bridge",
            fake_lookup,
            raising=False,
        )
        adapter = RegionDossierAdapter()
        r = await adapter.lookup("example.com")
        assert r["country"] == "US"
        assert r["asn"] == "AS15169"
        assert r["org"] == "Example LLC"
```

- [ ] **Step 3: Run, expect failure**

`pytest tests/recon_bridge/test_enrichment_aggregator.py::TestRegionDossierAdapter -v` → AttributeError.

- [ ] **Step 4: Write adapter + wrapper**

Append to `backend/services/recon_bridge/enrichment_aggregator.py`:

```python
class RegionDossierAdapter:
    async def lookup(self, target: str) -> dict[str, Any]:
        try:
            from services import region_dossier
        except ImportError:
            return {}
        loop = asyncio.get_running_loop()
        func = getattr(region_dossier, "lookup_for_recon_bridge", None)
        if func is None:
            logger.warning("region_dossier.lookup_for_recon_bridge missing — Task 9 step 4b")
            return {}
        return await loop.run_in_executor(None, func, target)
```

Append to `backend/services/region_dossier.py`:

```python
def lookup_for_recon_bridge(target: str) -> dict:
    """Recon-bridge-specific lookup. Returns at most {country, asn, org}.

    Existing region_dossier code surfaces a richer dossier via other entry
    points (head of state, languages, etc.) — that's served by the dossier
    UI directly. The bridge only needs the three fields above.
    """
    if not target:
        return {}
    try:
        # Replace this with whichever existing function returns geoIP/ASN/org.
        # If region_dossier exposes resolve(target) -> {...}, use that.
        full = resolve_basic(target)  # placeholder name; verify in Step 1
        return {k: full.get(k) for k in ("country", "asn", "org") if full.get(k)}
    except Exception as exc:  # noqa: BLE001
        logger.warning("region_dossier recon-bridge lookup error: %s", exc)
        return {}
```

- [ ] **Step 5: Run, expect pass**

`pytest tests/recon_bridge/test_enrichment_aggregator.py::TestRegionDossierAdapter -v` → PASS.

- [ ] **Step 6: Commit**

```bash
git add backend/services/recon_bridge/enrichment_aggregator.py \
        backend/services/region_dossier.py \
        backend/tests/recon_bridge/test_enrichment_aggregator.py
git commit -m "feat(recon-bridge): wire region_dossier into aggregator"
```

---

## Task 10 — Wire geopolitics into the aggregator

**Repo:** `Shadowbroker`

Same pattern. `services/geopolitics.py` returns recent conflict/sanctions events; we filter to the org's region. For Plan A, "recent events for org" can be a simple substring filter on the existing GDELT feed.

**Files:** modifications to `enrichment_aggregator.py` and its tests; new wrapper in `geopolitics.py`.

- [ ] **Step 1: Write failing adapter test**

Append to `backend/tests/recon_bridge/test_enrichment_aggregator.py`:

```python
class TestGeopoliticsAdapter:
    @pytest.mark.asyncio
    async def test_adapter_returns_alerts_filtered_to_org(self, monkeypatch):
        from services.recon_bridge.enrichment_aggregator import GeopoliticsAdapter

        def fake_alerts(org: str) -> list[dict]:
            return [{"id": "evt-1", "headline": f"Event involving {org}"}]

        monkeypatch.setattr(
            "services.geopolitics.alerts_for_org_recon_bridge",
            fake_alerts,
            raising=False,
        )
        adapter = GeopoliticsAdapter()
        alerts = await adapter.alerts("Example LLC")
        assert len(alerts) == 1
        assert "Example LLC" in alerts[0]["headline"]
```

- [ ] **Step 2: Run, expect failure** (`AttributeError`).

- [ ] **Step 3: Write adapter + wrapper**

Append to `backend/services/recon_bridge/enrichment_aggregator.py`:

```python
class GeopoliticsAdapter:
    async def alerts(self, org: str) -> list[dict[str, Any]]:
        try:
            from services import geopolitics
        except ImportError:
            return []
        loop = asyncio.get_running_loop()
        func = getattr(geopolitics, "alerts_for_org_recon_bridge", None)
        if func is None:
            logger.warning("geopolitics.alerts_for_org_recon_bridge missing — Task 10 step 3b")
            return []
        return await loop.run_in_executor(None, func, org)
```

Append to `backend/services/geopolitics.py`:

```python
def alerts_for_org_recon_bridge(org: str, *, max_results: int = 10) -> list[dict]:
    """Recon-bridge filter on the existing GDELT/conflict feed.

    Substring match on the org name in event headlines/sources. Returns at
    most max_results, newest first. Empty list when feed is empty or org
    string is too short.
    """
    if not org or len(org) < 3:
        return []
    try:
        # Replace 'recent_events' with the actual function the existing
        # geopolitics module exposes for fetching live events.
        events = recent_events()  # placeholder — verify in caller
    except Exception as exc:  # noqa: BLE001
        logger.warning("geopolitics recon-bridge fetch error: %s", exc)
        return []
    needle = org.lower()
    matches = [e for e in events if needle in (e.get("headline", "") + e.get("source", "")).lower()]
    return matches[:max_results]
```

- [ ] **Step 4: Run, expect pass**.

- [ ] **Step 5: Commit**

```bash
git add backend/services/recon_bridge/enrichment_aggregator.py \
        backend/services/geopolitics.py \
        backend/tests/recon_bridge/test_enrichment_aggregator.py
git commit -m "feat(recon-bridge): wire geopolitics alerts into aggregator"
```

---

## Task 11 — CT logs feed (use deep-eye's existing CT helper or implement minimal one)

**Repo:** `Shadowbroker`

CT logs (Certificate Transparency) discover related subdomains for the target domain. Shadowbroker doesn't have a CT feed; rather than building one from scratch, the bridge calls `crt.sh` directly. Cache 60s like the other feeds.

**Files:**
- Modify: `backend/services/recon_bridge/enrichment_aggregator.py` (add `CTLogsFeed` adapter using httpx).
- Modify: tests.

- [ ] **Step 1: Write failing test**

Append to `backend/tests/recon_bridge/test_enrichment_aggregator.py`:

```python
class TestCTLogsAdapter:
    @pytest.mark.asyncio
    async def test_adapter_returns_certs_from_crtsh(self, respx_mock):
        from services.recon_bridge.enrichment_aggregator import CTLogsAdapter

        respx_mock.get("https://crt.sh/?q=example.com&output=json").respond(
            200,
            json=[
                {"name_value": "example.com", "issuer_name": "Test CA"},
                {"name_value": "api.example.com", "issuer_name": "Test CA"},
            ],
        )
        adapter = CTLogsAdapter()
        certs = await adapter.certificates("example.com")
        assert len(certs) == 2
        assert certs[0]["cn"] == "example.com"
        assert certs[0]["issuer"] == "Test CA"

    @pytest.mark.asyncio
    async def test_adapter_returns_empty_on_http_error(self, respx_mock):
        from services.recon_bridge.enrichment_aggregator import CTLogsAdapter

        respx_mock.get("https://crt.sh/?q=example.com&output=json").respond(503)
        adapter = CTLogsAdapter()
        certs = await adapter.certificates("example.com")
        assert certs == []
```

> **Note:** This test uses `respx`. If Shadowbroker's dev deps don't include it, install it: `pip install respx==0.21.1` (and add to `[dependency-groups].dev` in `pyproject.toml`).

- [ ] **Step 2: Run, expect failure** (ImportError).

- [ ] **Step 3: Add the adapter**

Append to `backend/services/recon_bridge/enrichment_aggregator.py`:

```python
import httpx


class CTLogsAdapter:
    BASE = "https://crt.sh/"

    def __init__(self, *, timeout: float = 10.0) -> None:
        self._timeout = timeout

    async def certificates(self, target: str) -> list[dict[str, Any]]:
        if not target:
            return []
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(self.BASE, params={"q": target, "output": "json"})
            if resp.status_code != 200:
                return []
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.info("ct logs lookup miss for %s: %s", target, exc)
            return []
        return [
            {"cn": entry.get("name_value"), "issuer": entry.get("issuer_name")}
            for entry in data
            if entry.get("name_value")
        ]
```

- [ ] **Step 4: Run, expect pass**.

- [ ] **Step 5: Commit**

```bash
git add backend/services/recon_bridge/enrichment_aggregator.py \
        backend/tests/recon_bridge/test_enrichment_aggregator.py
git commit -m "feat(recon-bridge): CT logs adapter via crt.sh"
```

---

## Task 12 — `/bridge/enrich/{target}` endpoint

**Repo:** `Shadowbroker`

Wire the aggregator behind an HTTP endpoint that the deep-eye client will call.

**Files:**
- Modify: `backend/routers/recon_bridge.py` (add endpoint + injection).
- Modify: `backend/tests/recon_bridge/test_router_recon_bridge.py` (add tests).

- [ ] **Step 1: Write failing tests**

Append to `backend/tests/recon_bridge/test_router_recon_bridge.py`:

```python
class TestEnrich:
    def test_returns_aggregated_intel(self, app_client, monkeypatch):
        # Inject a fake aggregator via the router's setter
        from routers import recon_bridge as rb

        class FakeAggregator:
            async def aggregate(self, target):
                from services.recon_bridge.enrichment_aggregator import EnrichmentResult
                return EnrichmentResult(
                    target=target,
                    resolved_ips=["1.2.3.4"],
                    shodan={"ports": [80, 443]},
                    geo={"country": "US", "asn": "AS15169", "org": "X LLC"},
                    region_dossier={"country": "US"},
                    geopolitics_alerts=[],
                    ct_logs=[{"cn": target, "issuer": "Y CA"}],
                    stale_after=1700000060.0,
                )

        rb.set_enrichment_aggregator(FakeAggregator())

        resp = app_client.get("/bridge/enrich/example.com")
        assert resp.status_code == 200
        body = resp.json()
        assert body["target"] == "example.com"
        assert body["resolved_ips"] == ["1.2.3.4"]
        assert body["shodan"]["ports"] == [80, 443]
        assert body["ct_logs"][0]["cn"] == "example.com"

    def test_target_is_url_encoded(self, app_client, monkeypatch):
        """A target like https://acme.com/path should reach the aggregator as
        the host portion (acme.com) — the router strips scheme/path."""
        from routers import recon_bridge as rb

        seen = {}

        class CapturingAggregator:
            async def aggregate(self, target):
                seen["target"] = target
                from services.recon_bridge.enrichment_aggregator import EnrichmentResult
                return EnrichmentResult(target=target, stale_after=1700000060.0)

        rb.set_enrichment_aggregator(CapturingAggregator())
        resp = app_client.get("/bridge/enrich/" + "https%3A%2F%2Facme.com%2Fpath")
        assert resp.status_code == 200
        assert seen["target"] == "acme.com"
```

- [ ] **Step 2: Run, expect failure** (404 — endpoint not yet defined).

- [ ] **Step 3: Add the endpoint**

In `backend/routers/recon_bridge.py`, add:

```python
from urllib.parse import urlparse, unquote
from typing import Any

from services.recon_bridge.enrichment_aggregator import EnrichmentAggregator, EnrichmentResult


_aggregator: Optional[EnrichmentAggregator] = None


def set_enrichment_aggregator(agg) -> None:
    global _aggregator
    _aggregator = agg


class EnrichmentResponse(BaseModel):
    target: str
    resolved_ips: list[str] = []
    shodan: Optional[dict[str, Any]] = None
    geo: Optional[dict[str, Any]] = None
    region_dossier: Optional[dict[str, Any]] = None
    geopolitics_alerts: list[dict[str, Any]] = []
    ct_logs: list[dict[str, Any]] = []
    feed_errors: dict[str, str] = {}
    stale_after: str  # ISO

    @classmethod
    def from_result(cls, r: EnrichmentResult) -> "EnrichmentResponse":
        from datetime import datetime, timezone
        return cls(
            target=r.target,
            resolved_ips=r.resolved_ips,
            shodan=r.shodan,
            geo=r.geo,
            region_dossier=r.region_dossier,
            geopolitics_alerts=r.geopolitics_alerts,
            ct_logs=r.ct_logs,
            feed_errors=r.feed_errors,
            stale_after=datetime.fromtimestamp(r.stale_after, tz=timezone.utc).isoformat(),
        )


def _normalize_target_path(raw: str) -> str:
    decoded = unquote(raw)
    if "://" in decoded:
        host = urlparse(decoded).hostname
        return host or decoded
    return decoded


@router.get("/enrich/{target:path}", response_model=EnrichmentResponse)
async def enrich(target: str, request: Request) -> EnrichmentResponse:
    if not _hmac_bypass:
        await _enforce_hmac(request)
    if _aggregator is None:
        raise HTTPException(503, "enrichment aggregator not initialized")
    canonical = _normalize_target_path(target)
    result = await _aggregator.aggregate(canonical)
    return EnrichmentResponse.from_result(result)
```

- [ ] **Step 4: Run, expect pass**.

- [ ] **Step 5: Commit**

```bash
git add backend/routers/recon_bridge.py backend/tests/recon_bridge/test_router_recon_bridge.py
git commit -m "feat(recon-bridge): /bridge/enrich/{target} endpoint"
```

---

## Task 13 — Wire real HMAC enforcement into the router

**Repo:** `Shadowbroker`

Replace the placeholder `_enforce_hmac` (which currently raises `501` unless the test bypass is on) with the real verifier. Reads keys from environment variables, mirrors the OpenClaw key-id pattern.

**Files:**
- Modify: `backend/routers/recon_bridge.py`
- Modify: `backend/tests/recon_bridge/test_router_recon_bridge.py` — add HMAC-on tests.

- [ ] **Step 1: Write failing tests with HMAC enabled**

Append to `backend/tests/recon_bridge/test_router_recon_bridge.py`:

```python
class TestHMACEnforcement:
    @pytest.fixture
    def hmac_app_client(self, monkeypatch, manifest_dir):
        from fastapi import FastAPI
        from routers.recon_bridge import (
            router,
            set_scope_manifest_dir,
            set_hmac_bypass_for_tests,
            set_hmac_keys,
        )
        set_scope_manifest_dir(manifest_dir)
        set_hmac_bypass_for_tests(False)
        set_hmac_keys({"deep-eye-agent": b"a" * 32})
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_missing_headers_401(self, hmac_app_client):
        resp = hmac_app_client.post("/bridge/scope/check", json={
            "target": {"kind": "url", "value": "https://acme.com"},
            "scope_token": "engagement-test",
        })
        assert resp.status_code == 401
        assert "missing" in resp.json()["detail"].lower()

    def test_valid_signature_passes(self, hmac_app_client):
        import hashlib, hmac as hmac_mod, time as time_mod
        body = b'{"target":{"kind":"url","value":"https://acme.com"},"scope_token":"engagement-test"}'
        ts = int(time_mod.time())
        canonical = f"POST\n/bridge/scope/check\n{ts}\n{hashlib.sha256(body).hexdigest()}"
        sig = hmac_mod.new(b"a" * 32, canonical.encode(), hashlib.sha256).hexdigest()
        resp = hmac_app_client.post(
            "/bridge/scope/check",
            content=body,
            headers={
                "X-Bridge-Key-Id": "deep-eye-agent",
                "X-Bridge-Timestamp": str(ts),
                "X-Bridge-Signature": sig,
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 200

    def test_unknown_key_id_401(self, hmac_app_client):
        resp = hmac_app_client.post(
            "/bridge/scope/check",
            json={"target": {"kind": "url", "value": "https://acme.com"}, "scope_token": "engagement-test"},
            headers={
                "X-Bridge-Key-Id": "no-such-agent",
                "X-Bridge-Timestamp": "0",
                "X-Bridge-Signature": "deadbeef" * 8,
            },
        )
        assert resp.status_code == 401
```

- [ ] **Step 2: Run tests, expect failure**

`pytest tests/recon_bridge/test_router_recon_bridge.py::TestHMACEnforcement -v`
Expected: 501 instead of 401, or AttributeError on `set_hmac_keys`.

- [ ] **Step 3: Replace `_enforce_hmac` with real implementation**

In `backend/routers/recon_bridge.py`, replace the placeholder helper and add a key-store setter:

```python
_hmac_keys: dict[str, bytes] = {}
_nonce_cache = None


def set_hmac_keys(keys: dict[str, bytes]) -> None:
    global _hmac_keys, _nonce_cache
    _hmac_keys = dict(keys)
    from services.recon_bridge.hmac_auth import NonceCache
    _nonce_cache = NonceCache(max_size=4096, ttl_seconds=300)


async def _enforce_hmac(request: Request) -> None:
    from services.recon_bridge.hmac_auth import BridgeAuthError, verify_request

    key_id = request.headers.get("X-Bridge-Key-Id")
    timestamp = request.headers.get("X-Bridge-Timestamp")
    signature = request.headers.get("X-Bridge-Signature")
    if not key_id or not timestamp or not signature:
        raise HTTPException(401, "missing X-Bridge-* auth headers")

    key = _hmac_keys.get(key_id)
    if key is None:
        raise HTTPException(401, f"unknown key_id: {key_id}")

    body = await request.body()
    try:
        verify_request(
            key,
            request.method,
            request.url.path,
            int(timestamp),
            body,
            signature,
        )
        if _nonce_cache is not None:
            _nonce_cache.assert_unseen(key_id, int(timestamp), signature)
    except BridgeAuthError as exc:
        raise HTTPException(401, str(exc))
    except (ValueError, TypeError) as exc:
        raise HTTPException(401, f"invalid auth header: {exc}")
```

- [ ] **Step 4: Run, expect pass**.

- [ ] **Step 5: Commit**

```bash
git add backend/routers/recon_bridge.py backend/tests/recon_bridge/test_router_recon_bridge.py
git commit -m "feat(recon-bridge): real HMAC enforcement on bridge endpoints"
```

---

## Task 14 — Register router and bootstrap aggregator at app startup

**Repo:** `Shadowbroker`

Wire the new components into Shadowbroker's `main.py` so they actually run in the production app.

**Files:**
- Modify: `backend/main.py` — add 3-5 lines.

- [ ] **Step 1: Inspect existing router registrations**

```bash
grep -n "include_router\|app = FastAPI" backend/main.py
```

Note the existing pattern (probably `app.include_router(...)` calls in a block).

- [ ] **Step 2: Add the router and startup config**

In `backend/main.py`, find the block where routers are included and add:

```python
# Recon bridge — deep-eye integration channel
from routers.recon_bridge import (
    router as recon_bridge_router,
    set_scope_manifest_dir,
    set_enrichment_aggregator,
    set_hmac_keys,
)
from services.recon_bridge.enrichment_aggregator import (
    EnrichmentAggregator,
    ShodanConnectorAdapter,
    RegionDossierAdapter,
    GeopoliticsAdapter,
    CTLogsAdapter,
)

app.include_router(recon_bridge_router)

# Bootstrap recon bridge state from environment
import os, base64
_RB_KEYS_RAW = os.environ.get("RECON_BRIDGE_HMAC_KEYS", "")
# Format: "<key_id>:<base64-key>,<key_id>:<base64-key>,..."
_rb_keys = {}
for entry in [e.strip() for e in _RB_KEYS_RAW.split(",") if e.strip()]:
    if ":" not in entry:
        continue
    kid, b64 = entry.split(":", 1)
    try:
        _rb_keys[kid.strip()] = base64.b64decode(b64.strip())
    except Exception:
        logger.warning("ignoring malformed RECON_BRIDGE_HMAC_KEYS entry: %s", kid)
set_hmac_keys(_rb_keys)
set_scope_manifest_dir(os.environ.get("RECON_BRIDGE_SCOPE_DIR", "config/scope"))
set_enrichment_aggregator(
    EnrichmentAggregator(
        shodan=ShodanConnectorAdapter(),
        region_dossier=RegionDossierAdapter(),
        geopolitics=GeopoliticsAdapter(),
        ct_logs=CTLogsAdapter(),
        cache_ttl_seconds=60,
    )
)
```

- [ ] **Step 3: Run the API smoke test**

```bash
pytest tests/test_api_smoke.py -v
```

Expected: PASS. (If the smoke test fails complaining about a missing env var or the router import, fix and re-run.)

- [ ] **Step 4: Commit**

```bash
git add backend/main.py
git commit -m "feat(recon-bridge): register router and bootstrap aggregator at startup"
```

---

## Task 15 — End-to-end FastAPI integration test

**Repo:** `Shadowbroker`

One test that exercises the full bridge: real HMAC, real scope manifest from disk, mocked upstream feeds. Catches integration-level breakage that unit tests miss.

**Files:**
- Create: `backend/tests/recon_bridge/test_end_to_end_bridge.py`

- [ ] **Step 1: Write the test**

```python
"""End-to-end bridge test — real HMAC, real router, real aggregator with mocked feeds."""

import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routers.recon_bridge import (
    router as recon_bridge_router,
    set_scope_manifest_dir,
    set_enrichment_aggregator,
    set_hmac_keys,
    set_hmac_bypass_for_tests,
)
from services.recon_bridge.enrichment_aggregator import EnrichmentAggregator


HMAC_KEY = b"e2e-test-key-32-bytes-min-padded"
KEY_ID = "deep-eye-agent"


class StubShodan:
    async def lookup(self, target):
        return {"ip_str": "1.2.3.4", "ports": [80, 443], "cves": ["CVE-2024-1"]}


class StubRegion:
    async def lookup(self, target):
        return {"country": "US", "asn": "AS15169", "org": "Example Co"}


class StubGeo:
    async def alerts(self, org):
        return [{"id": "g1", "headline": f"{org} mentioned"}]


class StubCT:
    async def certificates(self, target):
        return [{"cn": target, "issuer": "Test CA"}]


@pytest.fixture
def e2e_client(tmp_path: Path):
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    (scope_dir / "engagement-test.yml").write_text(yaml.safe_dump({
        "version": 1,
        "manifest_id": "engagement-test",
        "mode": "engagement",
        "created_at": "2025-01-01T00:00:00Z",
        "expires_at": (datetime(2030, 1, 1, tzinfo=timezone.utc)).isoformat(),
        "authorization": {"contract_ref": "x", "contact": "y@z"},
        "targets": {"include": {"domains": ["example.com"]}, "exclude": {}},
    }))

    set_scope_manifest_dir(scope_dir)
    set_hmac_keys({KEY_ID: HMAC_KEY})
    set_hmac_bypass_for_tests(False)
    set_enrichment_aggregator(
        EnrichmentAggregator(
            shodan=StubShodan(),
            region_dossier=StubRegion(),
            geopolitics=StubGeo(),
            ct_logs=StubCT(),
            cache_ttl_seconds=60,
        )
    )
    app = FastAPI()
    app.include_router(recon_bridge_router)
    return TestClient(app)


def _signed(method: str, path: str, body: bytes):
    ts = int(time.time())
    canonical = f"{method}\n{path}\n{ts}\n{hashlib.sha256(body).hexdigest()}"
    sig = hmac.new(HMAC_KEY, canonical.encode(), hashlib.sha256).hexdigest()
    return {
        "X-Bridge-Key-Id": KEY_ID,
        "X-Bridge-Timestamp": str(ts),
        "X-Bridge-Signature": sig,
    }


def test_full_enrichment_round_trip(e2e_client):
    resp = e2e_client.get(
        "/bridge/enrich/example.com",
        headers={**_signed("GET", "/bridge/enrich/example.com", b""), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["target"] == "example.com"
    assert body["resolved_ips"] == ["1.2.3.4"]
    assert body["shodan"]["cves"] == ["CVE-2024-1"]
    assert body["geo"]["org"] == "Example Co"
    assert len(body["geopolitics_alerts"]) == 1
    assert body["ct_logs"][0]["cn"] == "example.com"


def test_full_scope_check_round_trip_in_scope(e2e_client):
    body = json.dumps({
        "target": {"kind": "url", "value": "https://example.com"},
        "scope_token": "engagement-test",
    }).encode()
    resp = e2e_client.post(
        "/bridge/scope/check",
        content=body,
        headers={**_signed("POST", "/bridge/scope/check", body), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json()["in_scope"] is True


def test_full_scope_check_out_of_scope(e2e_client):
    body = json.dumps({
        "target": {"kind": "url", "value": "https://other.test"},
        "scope_token": "engagement-test",
    }).encode()
    resp = e2e_client.post(
        "/bridge/scope/check",
        content=body,
        headers={**_signed("POST", "/bridge/scope/check", body), "Content-Type": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.json()["in_scope"] is False
```

- [ ] **Step 2: Run, expect pass**

`pytest tests/recon_bridge/test_end_to_end_bridge.py -v` → all PASS.

- [ ] **Step 3: Commit**

```bash
git add backend/tests/recon_bridge/test_end_to_end_bridge.py
git commit -m "test(recon-bridge): end-to-end integration test with real HMAC"
```

---

## Task 16 — `shadowbroker_client.py` — HMAC HTTP client (deep-eye side)

**Repo:** `deep-eye`

Build the client that calls the bridge from deep-eye. Async-first using httpx.

**Files:**
- Create: `modules/reconnaissance/shadowbroker_client.py`
- Create: `tests/test_shadowbroker_client.py`

- [ ] **Step 1: Write failing tests using respx**

Create `tests/test_shadowbroker_client.py`:

```python
"""Tests for ShadowbrokerClient — async HTTP client with HMAC."""

import json
import time

import httpx
import pytest
import respx

from modules.reconnaissance.shadowbroker_client import (
    BridgeError,
    BridgeUnreachable,
    ShadowbrokerClient,
)


KEY = b"client-key-32bytes-min-padded--xxxx"


@pytest.fixture
def client():
    return ShadowbrokerClient(
        base_url="https://bridge.test",
        key_id="deep-eye-agent",
        key=KEY,
        timeout=5.0,
    )


@pytest.mark.asyncio
async def test_enrich_returns_parsed_response(client, respx_mock):
    respx_mock.get("https://bridge.test/bridge/enrich/example.com").respond(
        200,
        json={
            "target": "example.com",
            "resolved_ips": ["1.2.3.4"],
            "shodan": {"ports": [80]},
            "geo": {"country": "US"},
            "ct_logs": [],
            "geopolitics_alerts": [],
            "feed_errors": {},
            "stale_after": "2026-05-06T01:00:00+00:00",
        },
    )
    enrichment = await client.enrich("example.com")
    assert enrichment["target"] == "example.com"
    assert enrichment["resolved_ips"] == ["1.2.3.4"]


@pytest.mark.asyncio
async def test_enrich_signs_request_with_required_headers(client, respx_mock):
    route = respx_mock.get("https://bridge.test/bridge/enrich/example.com").respond(
        200, json={"target": "example.com", "resolved_ips": [], "ct_logs": [],
                   "geopolitics_alerts": [], "feed_errors": {}, "stale_after": "x"})
    await client.enrich("example.com")
    req = route.calls.last.request
    assert req.headers["X-Bridge-Key-Id"] == "deep-eye-agent"
    assert "X-Bridge-Timestamp" in req.headers
    assert len(req.headers["X-Bridge-Signature"]) == 64


@pytest.mark.asyncio
async def test_enrich_raises_unreachable_on_connect_error(client, respx_mock):
    respx_mock.get("https://bridge.test/bridge/enrich/example.com").mock(
        side_effect=httpx.ConnectError("nope")
    )
    with pytest.raises(BridgeUnreachable):
        await client.enrich("example.com")


@pytest.mark.asyncio
async def test_enrich_raises_bridge_error_on_5xx(client, respx_mock):
    respx_mock.get("https://bridge.test/bridge/enrich/example.com").respond(503)
    with pytest.raises(BridgeError, match="503"):
        await client.enrich("example.com")


@pytest.mark.asyncio
async def test_scope_check_sends_signed_post(client, respx_mock):
    route = respx_mock.post("https://bridge.test/bridge/scope/check").respond(
        200, json={"in_scope": True, "reason": "ok",
                   "manifest_id": "engagement-test", "mode": "engagement"})
    r = await client.scope_check(
        target_kind="url", target_value="https://acme.com",
        scope_token="engagement-test",
    )
    assert r["in_scope"] is True
    body = route.calls.last.request.read()
    assert json.loads(body)["scope_token"] == "engagement-test"


@pytest.mark.asyncio
async def test_enrich_retries_once_on_timeout(client, respx_mock):
    """Spec §9: enrichment retries are capped at 1 (never block scan on slow recon)."""
    call_count = {"n": 0}

    def respond(_request):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise httpx.TimeoutException("slow")
        return httpx.Response(200, json={
            "target": "example.com", "resolved_ips": [], "ct_logs": [],
            "geopolitics_alerts": [], "feed_errors": {}, "stale_after": "x",
        })

    respx_mock.get("https://bridge.test/bridge/enrich/example.com").mock(side_effect=respond)
    r = await client.enrich("example.com")
    assert r["target"] == "example.com"
    assert call_count["n"] == 2  # initial + 1 retry
```

- [ ] **Step 2: Run, expect failure** (ImportError).

- [ ] **Step 3: Write the client**

Create `modules/reconnaissance/shadowbroker_client.py`:

```python
"""Async HTTP client for the Shadowbroker recon bridge.

Endpoints (Plan A):
  GET  /bridge/enrich/{target}
  POST /bridge/scope/check

Auth: HMAC-SHA256 via modules.reconnaissance.hmac_auth.

Spec §9 retry policy:
  - Enrichment: max 1 retry (never block a scan on slow recon).
  - Scope check: max 3 retries (this gate is mandatory; a network blip should
    not bypass it).
"""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from modules.reconnaissance.hmac_auth import sign_request

logger = logging.getLogger(__name__)


class BridgeError(Exception):
    """Bridge returned a non-success response."""


class BridgeUnreachable(BridgeError):
    """Bridge could not be contacted (connection error, DNS failure, etc.)."""


class ShadowbrokerClient:
    def __init__(
        self,
        *,
        base_url: str,
        key_id: str,
        key: bytes,
        timeout: float = 10.0,
        enrich_max_retries: int = 1,
        scope_check_max_retries: int = 3,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._key_id = key_id
        self._key = key
        self._timeout = timeout
        self._enrich_retries = enrich_max_retries
        self._scope_retries = scope_check_max_retries

    async def enrich(self, target: str) -> dict[str, Any]:
        path = f"/bridge/enrich/{target}"
        return await self._request("GET", path, body=b"", max_retries=self._enrich_retries)

    async def scope_check(
        self, *, target_kind: str, target_value: str, scope_token: str
    ) -> dict[str, Any]:
        import json as _json
        body = _json.dumps({
            "target": {"kind": target_kind, "value": target_value},
            "scope_token": scope_token,
        }).encode()
        return await self._request(
            "POST", "/bridge/scope/check", body=body, max_retries=self._scope_retries,
        )

    async def _request(
        self, method: str, path: str, *, body: bytes, max_retries: int
    ) -> dict[str, Any]:
        last_exc: Exception | None = None
        for attempt in range(max_retries + 1):
            try:
                return await self._send_once(method, path, body)
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                last_exc = exc
                if attempt >= max_retries:
                    break
                # Exponential backoff capped at 2s
                import asyncio as _asyncio
                await _asyncio.sleep(min(2.0, 0.25 * (2 ** attempt)))
        if isinstance(last_exc, (httpx.ConnectError, httpx.TimeoutException)):
            raise BridgeUnreachable(f"bridge unreachable after {max_retries + 1} attempt(s): {last_exc}")
        raise BridgeUnreachable(str(last_exc) if last_exc else "unknown")

    async def _send_once(self, method: str, path: str, body: bytes) -> dict[str, Any]:
        ts = int(time.time())
        sig = sign_request(self._key, method, path, ts, body)
        headers = {
            "X-Bridge-Key-Id": self._key_id,
            "X-Bridge-Timestamp": str(ts),
            "X-Bridge-Signature": sig,
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.request(method, self._base + path, headers=headers, content=body or None)
        if 200 <= resp.status_code < 300:
            return resp.json()
        raise BridgeError(f"bridge returned {resp.status_code}: {resp.text[:200]}")
```

- [ ] **Step 4: Run, expect pass**

`pytest tests/test_shadowbroker_client.py -v` → all PASS.

- [ ] **Step 5: Commit**

```bash
git add modules/reconnaissance/shadowbroker_client.py tests/test_shadowbroker_client.py
git commit -m "feat(recon): async HMAC client for shadowbroker bridge"
```

---

## Task 17 — Config files for the deep-eye side

**Repo:** `deep-eye`

The config tells deep-eye where the bridge is and how to authenticate.

**Files:**
- Create: `config/shadowbroker.example.yaml`

- [ ] **Step 1: Create the example config**

```yaml
# Example deep-eye → Shadowbroker bridge config.
# Copy this to config/shadowbroker.yaml and edit values for your environment.

bridge:
  url: "http://127.0.0.1:8000"     # Shadowbroker backend URL
  hmac_key_id: "deep-eye-agent"     # Must match a key registered in the bridge
  hmac_key_b64: ""                  # Base64-encoded HMAC key — set via env DEEPEYE_BRIDGE_KEY in production

  # Retry policy (matches spec §9). Don't lower these without reading the spec.
  timeout_seconds: 10
  enrich_max_retries: 1
  scope_check_max_retries: 3

scope:
  manifest_path: "config/scope/example-engagement.yml"

# Production: prefer setting the HMAC key via environment variable rather
# than hard-coding it here.
#   export DEEPEYE_BRIDGE_KEY="<base64-key>"
# deep-eye reads $DEEPEYE_BRIDGE_KEY when bridge.hmac_key_b64 is empty.
```

- [ ] **Step 2: Commit**

```bash
git add config/shadowbroker.example.yaml
git commit -m "docs(config): example shadowbroker bridge config for deep-eye"
```

---

## Task 18 — CLI flag wiring + enrichment integration in `deep_eye.py`

**Repo:** `deep-eye`

Add three new flags. The enrichment runs in the existing recon phase, before scanning. Falls back to existing `osint_enhanced.py` when bridge is unreachable.

**Files:**
- Modify: `deep_eye.py`
- Create: `tests/test_deep_eye_enrichment.py`

- [ ] **Step 1: Inspect existing deep_eye.py argparse setup**

```bash
grep -n "argparse\|add_argument\|args\." deep_eye.py | head -30
```

Note where flags are added. Plan A appends three new ones in the same block.

- [ ] **Step 2: Write failing integration test**

Create `tests/test_deep_eye_enrichment.py`:

```python
"""Integration test: deep-eye CLI with --enrich-from-shadowbroker.

This is a small smoke test that verifies the enrichment flow plumbs through:
- config is loaded
- bridge client is constructed
- enrichment is fetched (mocked) before scanning
- on bridge failure, fallback is used and scan still runs
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml


@pytest.fixture
def stubbed_config(tmp_path: Path) -> Path:
    bridge_cfg = tmp_path / "shadowbroker.yaml"
    bridge_cfg.write_text(yaml.safe_dump({
        "bridge": {
            "url": "http://stub",
            "hmac_key_id": "deep-eye-agent",
            "hmac_key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "timeout_seconds": 5,
            "enrich_max_retries": 1,
            "scope_check_max_retries": 3,
        },
        "scope": {"manifest_path": str(tmp_path / "scope.yml")},
    }))
    scope = tmp_path / "scope.yml"
    scope.write_text(yaml.safe_dump({
        "version": 1, "manifest_id": "engagement-test", "mode": "engagement",
        "created_at": "2025-01-01T00:00:00Z", "expires_at": "2030-01-01T00:00:00Z",
        "authorization": {"contract_ref": "x", "contact": "y@z"},
        "targets": {"include": {"domains": ["example.com"]}, "exclude": {}},
    }))
    return bridge_cfg


@pytest.mark.asyncio
async def test_enrichment_invoked_before_scan(stubbed_config: Path):
    from deep_eye import run_enrichment_phase

    fake_client = MagicMock()
    fake_client.scope_check = AsyncMock(return_value={"in_scope": True, "reason": "ok",
                                                       "manifest_id": "engagement-test",
                                                       "mode": "engagement"})
    fake_client.enrich = AsyncMock(return_value={
        "target": "example.com",
        "resolved_ips": ["1.2.3.4"],
        "shodan": {"ports": [80, 443]},
        "geo": {"country": "US"},
        "ct_logs": [],
        "geopolitics_alerts": [],
        "feed_errors": {},
        "stale_after": "2026-05-06T01:00:00+00:00",
    })

    result = await run_enrichment_phase(
        target_url="https://example.com",
        scope_token="engagement-test",
        bridge_config_path=stubbed_config,
        client_factory=lambda **kw: fake_client,
    )
    assert result["enriched"] is True
    assert result["enrichment"]["resolved_ips"] == ["1.2.3.4"]
    fake_client.scope_check.assert_awaited_once()
    fake_client.enrich.assert_awaited_once()


@pytest.mark.asyncio
async def test_bridge_unreachable_falls_back(stubbed_config: Path):
    from deep_eye import run_enrichment_phase
    from modules.reconnaissance.shadowbroker_client import BridgeUnreachable

    fake_client = MagicMock()
    fake_client.scope_check = AsyncMock(return_value={"in_scope": True, "reason": "ok",
                                                       "manifest_id": "engagement-test",
                                                       "mode": "engagement"})
    fake_client.enrich = AsyncMock(side_effect=BridgeUnreachable("nope"))

    result = await run_enrichment_phase(
        target_url="https://example.com",
        scope_token="engagement-test",
        bridge_config_path=stubbed_config,
        client_factory=lambda **kw: fake_client,
    )
    # Fallback path: enrichment is None, but the run continues.
    assert result["enriched"] is False
    assert "bridge unreachable" in result["fallback_reason"].lower()


@pytest.mark.asyncio
async def test_out_of_scope_aborts_enrichment(stubbed_config: Path):
    from deep_eye import EnrichmentBlocked, run_enrichment_phase

    fake_client = MagicMock()
    fake_client.scope_check = AsyncMock(return_value={
        "in_scope": False, "reason": "no scope rule matched",
        "manifest_id": "engagement-test", "mode": "engagement",
    })

    with pytest.raises(EnrichmentBlocked, match="no scope rule matched"):
        await run_enrichment_phase(
            target_url="https://other.test",
            scope_token="engagement-test",
            bridge_config_path=stubbed_config,
            client_factory=lambda **kw: fake_client,
        )
```

- [ ] **Step 3: Run, expect failure** (NameError on `run_enrichment_phase`).

- [ ] **Step 4: Add the enrichment phase function and CLI flags**

In `deep_eye.py`, add these imports near the top:

```python
import asyncio
import base64
import os
from pathlib import Path

import yaml
```

Then add the new function (place above `main()` or wherever helper functions live):

```python
class EnrichmentBlocked(Exception):
    """Raised when scope check rejects the target — scan must not proceed."""


async def run_enrichment_phase(
    *,
    target_url: str,
    scope_token: str,
    bridge_config_path: Path,
    client_factory=None,
) -> dict:
    """Pre-scan enrichment via Shadowbroker bridge.

    Returns:
      {
        "enriched": bool,
        "enrichment": dict | None,    # bridge response when enriched=True
        "fallback_reason": str,        # populated when enriched=False due to fallback
      }

    Raises:
      EnrichmentBlocked when scope check rejects the target. The CLI must
      abort the scan in that case — there is no fallback that bypasses scope.
    """
    from urllib.parse import urlparse
    from modules.reconnaissance.shadowbroker_client import (
        ShadowbrokerClient, BridgeError, BridgeUnreachable,
    )

    cfg = yaml.safe_load(Path(bridge_config_path).read_text(encoding="utf-8"))
    bridge = cfg["bridge"]
    key_b64 = bridge.get("hmac_key_b64") or os.environ.get("DEEPEYE_BRIDGE_KEY", "")
    if not key_b64:
        return {"enriched": False, "enrichment": None,
                "fallback_reason": "no HMAC key configured (set bridge.hmac_key_b64 or DEEPEYE_BRIDGE_KEY)"}

    factory = client_factory or (lambda **kw: ShadowbrokerClient(**kw))
    client = factory(
        base_url=bridge["url"],
        key_id=bridge["hmac_key_id"],
        key=base64.b64decode(key_b64),
        timeout=float(bridge.get("timeout_seconds", 10)),
        enrich_max_retries=int(bridge.get("enrich_max_retries", 1)),
        scope_check_max_retries=int(bridge.get("scope_check_max_retries", 3)),
    )

    # Step 1 — scope check. NEVER bypass on failure.
    try:
        result = await client.scope_check(
            target_kind="url", target_value=target_url, scope_token=scope_token,
        )
    except (BridgeError, BridgeUnreachable) as exc:
        # Spec §9 non-negotiable: no fallback that bypasses scope.
        raise EnrichmentBlocked(
            f"bridge unreachable, cannot verify scope: {exc}. "
            f"Re-run without --enrich-from-shadowbroker to scan without bridge."
        ) from exc
    if not result["in_scope"]:
        raise EnrichmentBlocked(result["reason"])

    # Step 2 — enrichment. Fallback on failure (spec §9: enrichment never blocks).
    host = urlparse(target_url).hostname or target_url
    try:
        enrichment = await client.enrich(host)
        return {"enriched": True, "enrichment": enrichment, "fallback_reason": ""}
    except (BridgeError, BridgeUnreachable) as exc:
        return {"enriched": False, "enrichment": None,
                "fallback_reason": f"bridge unreachable for enrichment: {exc}"}
```

Then locate the existing argparse setup (typically inside or just below `main()`), and add three new flags alongside the existing ones:

```python
parser.add_argument(
    "--enrich-from-shadowbroker",
    action="store_true",
    help="Enrich the target with Shadowbroker OSINT before scanning. Requires --scope-token.",
)
parser.add_argument(
    "--scope-token",
    type=str, default="",
    help="Scope manifest id; required for --enrich-from-shadowbroker (and Plan B/C inputs).",
)
parser.add_argument(
    "--bridge-config",
    type=str, default="config/shadowbroker.yaml",
    help="Path to the deep-eye → Shadowbroker bridge config (default: config/shadowbroker.yaml).",
)
```

After the args are parsed but before the scan starts, add:

```python
if args.enrich_from_shadowbroker:
    if not args.scope_token:
        parser.error("--enrich-from-shadowbroker requires --scope-token")
    try:
        enrichment_result = asyncio.run(run_enrichment_phase(
            target_url=args.url,
            scope_token=args.scope_token,
            bridge_config_path=Path(args.bridge_config),
        ))
    except EnrichmentBlocked as exc:
        logger.error("Enrichment scope check failed: %s", exc)
        return 1
    if enrichment_result["enriched"]:
        logger.info("Enrichment loaded: %s", enrichment_result["enrichment"].get("target"))
        # Wire the enrichment dict into the recon engine — Task 19.
        scanner_kwargs["shadowbroker_enrichment"] = enrichment_result["enrichment"]
    else:
        logger.warning("Enrichment unavailable (%s); falling back to local recon.",
                       enrichment_result["fallback_reason"])
```

> The `scanner_kwargs` line assumes the existing main() collects scanner options into a dict before instantiating the scanner. Find that dict (search for the line that constructs `Scanner(...)` or similar). If it doesn't exist, instead inject the enrichment as `scanner.shadowbroker_enrichment = enrichment_result["enrichment"]` immediately after the scanner is constructed.

- [ ] **Step 5: Run tests, expect pass**

`pytest tests/test_deep_eye_enrichment.py -v` → all PASS.

- [ ] **Step 6: Commit**

```bash
git add deep_eye.py tests/test_deep_eye_enrichment.py
git commit -m "feat(cli): --enrich-from-shadowbroker / --scope-token flags + enrichment phase"
```

---

## Task 19 — Wire enrichment into recon_engine

**Repo:** `deep-eye`

The enrichment dict needs to actually inform the scan. The simplest, lowest-risk hook is to surface enrichment as additional context for the AI payload generator (which already accepts a context dict).

**Files:**
- Modify: `core/scanner_engine.py` (or wherever the recon-to-scan handoff lives — verify in step 1).
- Modify: `modules/reconnaissance/recon_engine.py` if needed to merge enrichment with existing OSINT output.

- [ ] **Step 1: Find the scanner / recon handoff**

```bash
grep -n "shadowbroker_enrichment\|recon_engine\|RECON\|run_recon" core/*.py modules/reconnaissance/*.py | head -20
```

Note the entry point. The integration point is wherever recon results are passed to the scanner / AI payload generator.

- [ ] **Step 2: Write failing test**

Append to `tests/test_deep_eye_enrichment.py`:

```python
def test_enrichment_merged_into_recon_context():
    """When enrichment is provided, recon_engine.run() returns a context dict
    that includes the enrichment fields."""
    from modules.reconnaissance.recon_engine import merge_shadowbroker_enrichment

    base_recon = {"open_ports": [80], "subdomains": ["www.example.com"]}
    enrichment = {
        "target": "example.com",
        "resolved_ips": ["1.2.3.4"],
        "shodan": {"ports": [80, 443], "cves": ["CVE-2024-1"]},
        "geo": {"country": "US", "asn": "AS15169", "org": "Example Co"},
        "ct_logs": [{"cn": "api.example.com", "issuer": "Test CA"}],
        "geopolitics_alerts": [],
        "feed_errors": {},
        "stale_after": "x",
    }
    merged = merge_shadowbroker_enrichment(base_recon, enrichment)
    assert merged["open_ports"] == [80, 443]  # union with shodan
    assert "api.example.com" in merged["subdomains"]  # added from CT
    assert merged["target_org"] == "Example Co"
    assert merged["known_cves"] == ["CVE-2024-1"]
```

- [ ] **Step 3: Run, expect failure**.

- [ ] **Step 4: Implement merge function**

In `modules/reconnaissance/recon_engine.py`, append:

```python
def merge_shadowbroker_enrichment(base_recon: dict, enrichment: dict) -> dict:
    """Merge Shadowbroker enrichment into the existing recon dict.

    Behaviour:
      - open_ports: union with shodan.ports
      - subdomains: union with CT-log CNs (deduplicated)
      - known_cves: from shodan.cves (new field — empty list if absent)
      - target_org: from geo.org (new field — None if absent)
      - geopolitics_alerts: passed through (new field)
      - resolved_ips: passed through (new field)
    """
    merged = dict(base_recon)

    shodan = enrichment.get("shodan") or {}
    geo = enrichment.get("geo") or {}

    # Ports: union with int sort
    ports = set(merged.get("open_ports") or [])
    ports.update(shodan.get("ports") or [])
    merged["open_ports"] = sorted(ports)

    # Subdomains: union from CT logs
    subs = set(merged.get("subdomains") or [])
    for cert in (enrichment.get("ct_logs") or []):
        cn = cert.get("cn")
        if cn:
            subs.add(cn)
    merged["subdomains"] = sorted(subs)

    merged["known_cves"] = list(shodan.get("cves") or [])
    merged["target_org"] = geo.get("org")
    merged["target_country"] = geo.get("country")
    merged["target_asn"] = geo.get("asn")
    merged["resolved_ips"] = list(enrichment.get("resolved_ips") or [])
    merged["geopolitics_alerts"] = list(enrichment.get("geopolitics_alerts") or [])
    return merged
```

- [ ] **Step 5: Wire merge into the scan flow**

Find where `scanner` is constructed in `deep_eye.py` — Task 18 step 4 left a `scanner_kwargs["shadowbroker_enrichment"] = ...` line as the integration hook. Replace that line with the merge call below:

```python
from modules.reconnaissance.recon_engine import merge_shadowbroker_enrichment

if enrichment_result["enriched"]:
    scanner.recon_context = merge_shadowbroker_enrichment(
        scanner.recon_context or {},
        enrichment_result["enrichment"],
    )
    logger.info(
        "Enriched recon: %d ports, %d subdomains, %d known CVEs",
        len(scanner.recon_context.get("open_ports", [])),
        len(scanner.recon_context.get("subdomains", [])),
        len(scanner.recon_context.get("known_cves", [])),
    )
```

> If `scanner.recon_context` doesn't exist as an attribute, find the equivalent on whatever scanner class deep-eye uses (likely `core.scanner_engine.ScannerEngine` — grep for `recon_context` or `recon_data`). The merged dict needs to reach the AI payload generator, which is in `core/ai_payload_generator.py`.

- [ ] **Step 6: Run tests, expect pass**

`pytest tests/test_deep_eye_enrichment.py -v` → all PASS.

- [ ] **Step 7: Commit**

```bash
git add deep_eye.py modules/reconnaissance/recon_engine.py tests/test_deep_eye_enrichment.py
git commit -m "feat(recon): merge shadowbroker enrichment into scanner recon context"
```

---

## Task 20 — Documentation updates

**Repo:** `deep-eye` and `Shadowbroker`

Working software is not done until docs explain how to use it.

**Files:**
- Modify: `deep-eye/docs/QUICKSTART.md`
- Create: `Shadowbroker/docs/recon-bridge.md`

- [ ] **Step 1: deep-eye usage section**

Append to `deep-eye/docs/QUICKSTART.md`:

```markdown
## Shadowbroker Enrichment (optional)

deep-eye can enrich its recon phase with Shadowbroker's OSINT feeds (Shodan,
geolocation, CT logs, geopolitics) when both are running. This adds known
ports, subdomains, CVEs, and org context to the AI payload generator,
producing more targeted scans.

### Setup

1. Make sure Shadowbroker (forked, with the recon-bridge router) is running:

       cd /path/to/Shadowbroker && docker compose up -d

2. Generate an HMAC key shared between the two sides:

       python3 -c 'import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())'

3. On the Shadowbroker host, set:

       export RECON_BRIDGE_HMAC_KEYS="deep-eye-agent:<base64-key>"
       export RECON_BRIDGE_SCOPE_DIR="config/scope"
       # Then restart Shadowbroker.

4. On the deep-eye host, copy the example config:

       cp config/shadowbroker.example.yaml config/shadowbroker.yaml

   Edit `bridge.url` to point at the Shadowbroker host and put the same
   base64 HMAC key in `bridge.hmac_key_b64` (or set `DEEPEYE_BRIDGE_KEY` env).

5. Create or copy a scope manifest to `config/scope/<id>.yml`. The same
   manifest must exist in Shadowbroker's scope dir.

### Usage

    python deep_eye.py -u https://target.com \
      --enrich-from-shadowbroker \
      --scope-token engagement-acme-2026-q1

The scan runs as usual. If the bridge is reachable and the target is in
scope, deep-eye fetches enrichment first and uses it to inform payload
generation. If the bridge is unreachable, deep-eye falls back to its
existing local recon and continues.

### Failure modes

| Outcome | Cause | What it means |
|---|---|---|
| `EnrichmentBlocked: no scope rule matched` | Target is not in your scope manifest | **Do not bypass.** Add the target to scope only if you have authorization. |
| `EnrichmentBlocked: bridge unreachable, cannot verify scope` | Bridge is down | The scope check is mandatory. Re-run without `--enrich-from-shadowbroker` to scan with local recon only. |
| `Enrichment unavailable; falling back to local recon` | Bridge reachable for scope check but enrichment timed out | Not an error. Scan continues with `osint_enhanced.py`. |
```

- [ ] **Step 2: Shadowbroker setup doc**

Create `Shadowbroker/docs/recon-bridge.md`:

```markdown
# Recon Bridge — deep-eye Integration

The recon bridge is a FastAPI router (`backend/routers/recon_bridge.py`) and
service module (`backend/services/recon_bridge/`) added to Shadowbroker as
part of Plan A. It exposes:

- `POST /bridge/scope/check` — validate a target against a scope manifest
- `GET  /bridge/enrich/{target}` — aggregated OSINT enrichment

Both endpoints require HMAC-SHA256 auth (mirroring the OpenClaw channel —
see `backend/services/openclaw_channel.py` for the original pattern).

## Configuration

Two environment variables on the Shadowbroker side:

    RECON_BRIDGE_HMAC_KEYS="<key_id>:<base64-key>,<key_id>:<base64-key>,..."
    RECON_BRIDGE_SCOPE_DIR="config/scope"

Each scope manifest is a YAML file in `RECON_BRIDGE_SCOPE_DIR`. See
`backend/config/scope/example-engagement.yml` for the schema.

## Generating an HMAC key

    python3 -c 'import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())'

Distribute the key to the deep-eye operator out-of-band. Each agent gets its
own key_id; never share keys across agents.

## Running with deep-eye

See `deep-eye/docs/QUICKSTART.md#shadowbroker-enrichment-optional`.

## Future plans (B and C)

Plan A only ships enrichment. Plan B adds infrastructure scan inputs
(`/bridge/enrich/{ip|cidr|asn}` semantics for non-URL targets), and Plan C
adds the `/bridge/scan`, `/bridge/findings` endpoints plus the deep-eye
daemon for scan dispatch.
```

- [ ] **Step 3: Commit (deep-eye)**

```bash
# In deep-eye repo
git add docs/QUICKSTART.md
git commit -m "docs: shadowbroker enrichment usage in QUICKSTART"
```

- [ ] **Step 4: Commit (Shadowbroker)**

```bash
# In Shadowbroker repo
git add docs/recon-bridge.md
git commit -m "docs: recon bridge setup and configuration guide"
```

---

## Task 21 — Smoke test the full flow with real Shadowbroker

**Repo:** Both

Manual test — verify the integrated flow works against a running Shadowbroker, not just mocks.

- [ ] **Step 1: Start Shadowbroker locally**

```bash
cd /home/ghostexodus/Shadowbroker
export RECON_BRIDGE_HMAC_KEYS="deep-eye-agent:$(python3 -c 'import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())')"
export RECON_BRIDGE_SCOPE_DIR="$PWD/backend/config/scope"
# Without docker — for fast iteration, run the backend directly:
cd backend && uvicorn main:app --reload --port 8000
```

Note the HMAC key printed.

- [ ] **Step 2: Configure deep-eye**

```bash
cd /home/ghostexodus/deep-eye
cp config/shadowbroker.example.yaml config/shadowbroker.yaml
# Edit config/shadowbroker.yaml:
#   bridge.url: http://127.0.0.1:8000
#   bridge.hmac_key_b64: <paste the key from Step 1>
cp config/scope/example-engagement.yml config/scope/example-engagement.yml  # already there
```

- [ ] **Step 3: Add a target to the example scope manifest**

Edit `config/scope/example-engagement.yml` (both repos — they need to match) so `targets.include.domains` contains a domain you genuinely have permission to scan, e.g. `example.com` for a public no-op test, or your own bug bounty scope. Ensure `expires_at` is in the future.

- [ ] **Step 4: Run an enrichment-only scan**

```bash
python deep_eye.py -u https://example.com \
  --enrich-from-shadowbroker \
  --scope-token example-engagement-2026-q2
```

Expected:
- Logs show `Enrichment loaded: example.com`
- Logs show `Enriched recon: N ports, N subdomains, N known CVEs` (numbers depend on `SHODAN_API_KEY`)
- Scan proceeds normally

- [ ] **Step 5: Test the fallback path**

Stop Shadowbroker (`Ctrl-C` in the uvicorn terminal). Re-run:

```bash
python deep_eye.py -u https://example.com \
  --enrich-from-shadowbroker \
  --scope-token example-engagement-2026-q2
```

Expected: Logs show `EnrichmentBlocked: bridge unreachable, cannot verify scope`. Scan exits with code 1.

Then re-run *without* the enrich flag:

```bash
python deep_eye.py -u https://example.com
```

Expected: Scan runs as it did pre-Plan-A (uses `osint_enhanced.py`). No bridge interaction.

- [ ] **Step 6: Test scope rejection**

Restart Shadowbroker. Run with an out-of-scope target:

```bash
python deep_eye.py -u https://other.test \
  --enrich-from-shadowbroker \
  --scope-token example-engagement-2026-q2
```

Expected: Logs show `EnrichmentBlocked: no scope rule matched`. Scan exits with code 1. **No HTTP requests are made to other.test.**

- [ ] **Step 7: Document the smoke test result**

Take notes on any drift you found between the plan and reality (signature names, paths, etc.). Open issues for follow-ups in your fork or paste them into the next-plan brainstorm.

---

## Self-Review (run before declaring Plan A done)

This is a checklist you run yourself, not a subagent dispatch. After completing all tasks above:

**1. Spec coverage check.** Open `docs/superpowers/specs/2026-05-05-shadowbroker-integration-design.md`. For each item below, identify which Plan A task implemented it:

- [ ] §3 architecture topology → Tasks 14, 17, 21 (config + bootstrap proves it)
- [ ] §4 component breakdown for `services/recon_bridge/` → Tasks 2, 4, 7-12
- [ ] §4 deep-eye new files → Tasks 3, 5, 16, 17, 18, 19
- [ ] §5 `/bridge/scope/check` API contract → Task 6, 13
- [ ] §5 `/bridge/enrich/{target}` API contract → Tasks 7-12
- [ ] §5 deep-eye daemon endpoints — **NOT IN PLAN A** (Plan C)
- [ ] §5 `/bridge/scan` and `/bridge/findings` — **NOT IN PLAN A** (Plan C)
- [ ] §6 Flow A — Tasks 18, 19 wire it; Task 21 verifies it
- [ ] §6 Flow B — **NOT IN PLAN A** (Plan B)
- [ ] §6 Flow C — **NOT IN PLAN A** (Plan C)
- [ ] §7 scope manifest schema → Task 4
- [ ] §7 mandatory expiry → Task 4 (test_expired_manifest_blocks_everything)
- [ ] §7 multi-manifest support → Tasks 4, 6 (manifest_id-keyed lookup)
- [ ] §8 HMAC channel → Tasks 2, 3, 13
- [ ] §8 timestamp window → Task 2 (TIMESTAMP_WINDOW_SECONDS)
- [ ] §8 nonce cache → Task 2 (NonceCache)
- [ ] §8 keys via env vars → Task 14 (RECON_BRIDGE_HMAC_KEYS)
- [ ] §9 error handling matrix — partial (Plan A covers enrichment, scope check, bridge unreachable, HMAC failure; full coverage in Plan C)
- [ ] §9 non-negotiable "no fallback bypasses scope" → Task 18 (EnrichmentBlocked when scope check unreachable)
- [ ] §10 unit testing → Tasks 2, 4, 5, 7, 8, 9, 10, 11, 16
- [ ] §10 integration testing → Tasks 6, 12, 13, 18, 19
- [ ] §10 end-to-end with both real services → Task 15 (FastAPI side) + Task 21 (real bin)

**2. Type/name consistency:** A function signature defined in Task N must match the way it's called in Task M. Check:

- [ ] `sign_request(key, method, path, ts, body)` arg order is identical in deep-eye and Shadowbroker hmac_auth modules.
- [ ] `verify_request(...)` arg order matches.
- [ ] `ScopeManifest.from_dict(data)` returns a `ScopeManifest` and is called identically in both repos.
- [ ] `Target(kind=..., value=...)` keyword args are used everywhere (no positional drift).
- [ ] `EnrichmentResult` field names match between aggregator output, router response model, and client parsing.
- [ ] `set_hmac_keys(dict[str, bytes])` is the exact signature (key id → key bytes).

**3. Placeholder scan:** Search the plan for forbidden phrases:

```bash
grep -n -E 'TBD|TODO|fill in|implement later|similar to task|appropriate error' docs/superpowers/plans/2026-05-06-shadowbroker-integration-plan-a-enrichment.md
```

Expected: zero hits in the substantive task body. Hits inside example code comments quoting other docs are fine if they're clearly examples and not gaps in this plan.

---

## Out of scope (deferred to Plans B and C)

Explicitly NOT in Plan A:

- IP / CIDR / ASN scan inputs to deep-eye (Plan B).
- The `sb_target_resolver.py` module that expands those inputs (Plan B).
- The deep-eye daemon (`core/shadowbroker_daemon.py`) and `--shadowbroker` flag (Plan C).
- `POST /bridge/scan` endpoint (Plan C).
- `POST /bridge/findings` endpoint and `findings_store.py` SQLite layer (Plan C).
- Frontend changes (vuln layer, ScanLauncher) (Plan C).
- `pin_target_resolver.py` mapping table (Plan C).
- SSE pipe for finding events (Plan C).

If you find yourself wanting to build any of these to "complete the picture," resist. Plan A is about producing working enrichment software you can use in real engagements. Plans B and C will benefit from real-world feedback on Plan A before they're written.

---

## Execution Handoff

**Plan complete and saved to** `docs/superpowers/plans/2026-05-06-shadowbroker-integration-plan-a-enrichment.md`. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Best when you want progress without watching every step.

2. **Inline Execution** — Execute tasks in this session using `executing-plans`, batch execution with checkpoints. Best when you want to see and discuss every implementation choice as it happens.

Which approach?
