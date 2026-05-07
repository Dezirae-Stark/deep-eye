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


# Codex P1: validate() must handle Target.kind == "cidr". The Target dataclass
# documents "cidr" as a valid kind and _resolve_target_for_match parses it,
# but ScopeManifest.validate previously had no branch for it — every cidr
# target fell through to "no scope rule matched", so any client requesting
# CIDR-scope authorization got refused even when the CIDR was allow-listed.

@pytest.mark.parametrize("cidr,expected", [
    # Exact match against the allow-listed CIDR.
    ("198.51.100.0/24", True),
    # Strict subnet of the allow-listed CIDR.
    ("198.51.100.128/25", True),
    # Single-host CIDR inside the allow-listed CIDR.
    ("198.51.100.42/32", True),
    # Outside the allow-listed CIDR — must reject.
    ("10.0.0.0/24", False),
    # Superset of the allow-listed CIDR — must reject (broader than authorized).
    ("198.51.0.0/16", False),
])
def test_cidr_target_validates_against_include_cidrs(cidr, expected):
    m = _manifest()
    result = m.validate(Target(kind="cidr", value=cidr))
    assert result.in_scope is expected, (
        f"CIDR {cidr!r}: expected in_scope={expected}, got {result}"
    )


def test_cidr_target_with_malformed_value_rejected():
    """Garbage CIDR values must not 200-with-true; they should fall through
    to the default 'no scope rule matched' rejection path."""
    m = _manifest()
    result = m.validate(Target(kind="cidr", value="not-a-cidr"))
    assert result.in_scope is False
