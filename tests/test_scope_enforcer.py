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
    with caplog.at_level("INFO", logger="core.scope_enforcer"):
        r = e.check(Target("url", "https://other.test"))
    assert r.in_scope is False
    assert "no scope rule matched" in r.reason
    assert any("Local scope check rejected" in m for m in caplog.messages)


def test_manifest_is_lazily_loaded_and_cached(manifest_file: Path):
    e = ScopeEnforcer(manifest_file)
    m1 = e.manifest()
    m2 = e.manifest()
    assert m1 is m2  # cached, same instance
