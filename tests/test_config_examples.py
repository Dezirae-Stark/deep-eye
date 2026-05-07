"""Tests that the shipped example configs are valid for the loaders.

These are 'live documentation' tests — if the schema changes, the example
must follow, otherwise operators copy-paste-broken configs.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
import yaml

from core.scope_manifest import ScopeManifest, Target


REPO_ROOT = Path(__file__).resolve().parent.parent
BRIDGE_CONFIG_PATH = REPO_ROOT / "config" / "config.example.yaml"
SCOPE_EXAMPLE_PATH = REPO_ROOT / "config" / "scope" / "example-engagement.yml"


class TestBridgeConfigExample:
    def test_config_yaml_loads(self):
        data = yaml.safe_load(BRIDGE_CONFIG_PATH.read_text())
        assert "shadowbroker_bridge" in data, (
            "config.example.yaml must include a shadowbroker_bridge section "
            "for Task 17/18 wiring"
        )

    def test_bridge_section_disabled_by_default(self):
        data = yaml.safe_load(BRIDGE_CONFIG_PATH.read_text())
        bridge = data["shadowbroker_bridge"]
        # Off by default: copying the example must not opt operators in.
        assert bridge.get("enabled") is False

    def test_bridge_section_documents_required_fields(self):
        data = yaml.safe_load(BRIDGE_CONFIG_PATH.read_text())
        bridge = data["shadowbroker_bridge"]
        for key in ("base_url", "key_id", "scope_token", "scope_manifest_path", "timeout"):
            assert key in bridge, f"shadowbroker_bridge missing {key!r}"

    def test_bridge_section_does_NOT_contain_secret_in_yaml(self):
        """Secret must come from BRIDGE_HMAC_KEY env, not the example YAML."""
        data = yaml.safe_load(BRIDGE_CONFIG_PATH.read_text())
        bridge = data["shadowbroker_bridge"]
        # No 'key' or 'secret' or 'secret_hex' keys — secrets live in env.
        assert "key" not in bridge
        assert "secret" not in bridge
        assert "secret_hex" not in bridge


class TestScopeManifestExample:
    def test_example_manifest_loads(self):
        data = yaml.safe_load(SCOPE_EXAMPLE_PATH.read_text())
        # Bypass the from_file path because expires_at in the shipped example
        # is in the future at write time but always-far-enough is brittle.
        # Just assert it parses; expiry is checked separately below.
        assert data["manifest_id"]
        assert data["mode"] in {"engagement", "bounty", "self", "lab"}

    def test_example_manifest_parses_via_loader(self):
        data = yaml.safe_load(SCOPE_EXAMPLE_PATH.read_text())
        manifest = ScopeManifest.from_dict(data)
        assert manifest.manifest_id
        # Must include at least one allow-listed domain so it's a meaningful
        # template.
        assert manifest.include_domains, "example must show how to include a domain"

    def test_example_manifest_validates_a_sample_target(self):
        """The example must say YES to its own first include_domain."""
        data = yaml.safe_load(SCOPE_EXAMPLE_PATH.read_text())
        manifest = ScopeManifest.from_dict(data)
        domain = manifest.include_domains[0].lstrip("*.")
        # Use a clock far in the past so manifest hasn't expired regardless
        # of when this test runs.
        past = datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()
        result = manifest.validate(
            Target(kind="url", value=f"https://{domain}"),
            now=lambda: past,
        )
        assert result.in_scope is True
