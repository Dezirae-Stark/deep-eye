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
        "expires_at": (datetime.now(timezone.utc)
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
