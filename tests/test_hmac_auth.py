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
        # Frozen vector — seeded from known-good run; see Task 3 step 4.
        "b496801ac136ced315787382a245783f9ac671c9bbbfbca97fc66aa60b95deb5",
    ),
    (
        "POST",
        "/bridge/scope/check",
        1700000000,
        b'{"target":{"kind":"url","value":"https://x.test"}}',
        # Frozen vector — seeded from known-good run; see Task 3 step 4.
        "c78d0aba9e1f782b07614a42b6e9cb70e48802cccc660463089e590419880627",
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
