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


# Codex R2 P1: lab-mode region_lock only handled kind=="ip", but the CLI
# flow sends URL targets to scope_check. A lab manifest that uses
# region_lock instead of duplicating domain rules would reject every URL
# scan with "no scope rule matched" — defeating the purpose of region_lock.

def _lab_manifest(region_lock="198.51.100.0/24"):
    return ScopeManifest.from_dict({
        "version": 1,
        "manifest_id": "lab-test",
        "mode": "lab",
        "created_at": "2025-01-01T00:00:00Z",
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        "authorization": {"contract_ref": "x", "contact": "y@z"},
        "targets": {"include": {}, "exclude": {}},
        "lab": {"region_lock": region_lock},
    })


def _ai4(ip):
    """Build a single-IPv4 getaddrinfo result tuple list."""
    import socket
    return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]


def test_lab_region_lock_accepts_url_resolving_into_lock(monkeypatch):
    """A URL whose resolved IP is inside the lab region_lock must be
    accepted by the region rule alone — no domain include needed."""
    import socket
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, *a, **kw: _ai4("198.51.100.42")
                        if host == "lab.example" else _ai4("1.2.3.4"))

    m = _lab_manifest()
    result = m.validate(Target(kind="url", value="https://lab.example"))
    assert result.in_scope is True, f"got {result}"
    assert "lab region_lock" in result.reason


def test_lab_region_lock_rejects_url_resolving_outside_lock(monkeypatch):
    """A URL whose IP is outside the lab region_lock must be rejected with
    the region-lock reason (not 'no scope rule matched')."""
    import socket
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda host, *a, **kw: _ai4("10.0.0.1"))

    m = _lab_manifest()
    result = m.validate(Target(kind="url", value="https://elsewhere.example"))
    assert result.in_scope is False
    assert "outside lab region_lock" in result.reason


def test_lab_region_lock_rejects_url_with_unresolvable_host(monkeypatch):
    """If DNS fails, fall through cleanly — don't crash, and don't grant
    scope just because we couldn't check."""
    import socket
    def _fail(host, *a, **kw):
        raise socket.gaierror("nope")
    monkeypatch.setattr(socket, "getaddrinfo", _fail)

    m = _lab_manifest()
    result = m.validate(Target(kind="url", value="https://nonexistent.example"))
    assert result.in_scope is False


# Codex R3 P2: dd5d084 added URL→DNS resolution for lab region_lock but
# used socket.gethostbyname, which is IPv4-only. Lab manifests with an
# IPv6 region_lock or AAAA-only hosts get rejected even when in scope.
# Switch to getaddrinfo for dual-stack resolution. These three tests
# pin the new behavior.

def test_lab_region_lock_accepts_ipv6_aaaa_only_host(monkeypatch):
    """IPv6 region_lock + AAAA-only host: must accept via dual-stack
    resolution. The previous IPv4-only path returned None and skipped
    the region rule — silent denial of valid lab targets."""
    import socket

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == "lab6.example":
            return [(socket.AF_INET6, socket.SOCK_STREAM, 0, "",
                     ("2001:db8::42", 0, 0, 0))]
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    m = _lab_manifest(region_lock="2001:db8::/32")
    result = m.validate(Target(kind="url", value="https://lab6.example"))
    assert result.in_scope is True, f"got {result}"
    assert "lab region_lock" in result.reason


def test_lab_region_lock_accepts_when_any_resolved_address_matches(monkeypatch):
    """Dual-stack host (IPv4 + IPv6) with IPv4 region_lock: any matching
    address authorizes. Resolver order should not affect the outcome."""
    import socket

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if host == "lab.example":
            # IPv6 returned first (resolver-dependent order) but IPv4 is
            # the one that matches the lock.
            return [
                (socket.AF_INET6, socket.SOCK_STREAM, 0, "",
                 ("2001:db8::1", 0, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "",
                 ("198.51.100.42", 0)),
            ]
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    m = _lab_manifest(region_lock="198.51.100.0/24")
    result = m.validate(Target(kind="url", value="https://lab.example"))
    assert result.in_scope is True


def test_lab_region_lock_rejects_when_no_resolved_address_matches(monkeypatch):
    """All resolved addresses outside the lock → rejection with the
    region-lock reason (not 'no scope rule matched')."""
    import socket

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 0, "",
             ("fe80::1", 0, 0, 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    m = _lab_manifest(region_lock="198.51.100.0/24")
    result = m.validate(Target(kind="url", value="https://elsewhere.example"))
    assert result.in_scope is False
    assert "outside lab region_lock" in result.reason
