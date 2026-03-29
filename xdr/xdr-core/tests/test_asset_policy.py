#!/usr/bin/env python3
"""Tests for asset_policy — whitelist/blacklist YAML management."""

import sys
import pytest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from asset_policy import AssetPolicy


@pytest.fixture
def policy(tmp_path):
    """Create an AssetPolicy with temp YAML file."""
    yaml_file = tmp_path / "test_policy.yaml"
    with patch("asset_policy.POLICY_FILE", yaml_file), \
         patch("asset_policy.POLICY_FILE_DEV", yaml_file):
        p = AssetPolicy()
        yield p


class TestPolicyInit:
    """Policy initialization and loading."""

    def test_empty_policy_has_sections(self, policy):
        data = policy.get_all()
        assert "modules" in data
        assert "packages" in data
        assert "hardware" in data

    def test_each_section_has_lists(self, policy):
        for section in ("modules", "packages", "hardware"):
            data = policy.get_section(section)
            assert "whitelist" in data
            assert "blacklist" in data


class TestWhitelist:
    """Whitelist operations."""

    def test_add_to_whitelist(self, policy):
        result = policy.add_to_whitelist("modules", "nvidia")
        assert result["ok"]
        assert policy.is_whitelisted("modules", "nvidia")

    def test_not_whitelisted_by_default(self, policy):
        assert not policy.is_whitelisted("modules", "random_module")

    def test_add_duplicate(self, policy):
        policy.add_to_whitelist("modules", "test_mod")
        policy.add_to_whitelist("modules", "test_mod")
        data = policy.get_section("modules")
        assert data["whitelist"].count("test_mod") == 1


class TestBlacklist:
    """Blacklist operations."""

    def test_add_to_blacklist(self, policy):
        result = policy.add_to_blacklist("packages", "nmap")
        assert result["ok"]
        assert policy.is_blacklisted("packages", "nmap")

    def test_blacklist_removes_from_whitelist(self, policy):
        policy.add_to_whitelist("modules", "conflicting_mod")
        assert policy.is_whitelisted("modules", "conflicting_mod")

        policy.add_to_blacklist("modules", "conflicting_mod")
        assert policy.is_blacklisted("modules", "conflicting_mod")
        assert not policy.is_whitelisted("modules", "conflicting_mod")

    def test_whitelist_removes_from_blacklist(self, policy):
        policy.add_to_blacklist("modules", "switch_mod")
        assert policy.is_blacklisted("modules", "switch_mod")

        policy.add_to_whitelist("modules", "switch_mod")
        assert policy.is_whitelisted("modules", "switch_mod")
        assert not policy.is_blacklisted("modules", "switch_mod")


class TestRemove:
    """Remove from lists."""

    def test_remove_from_whitelist(self, policy):
        policy.add_to_whitelist("modules", "to_remove")
        result = policy.remove_from_list("modules", "whitelist", "to_remove")
        assert result["ok"]
        assert not policy.is_whitelisted("modules", "to_remove")

    def test_remove_nonexistent(self, policy):
        result = policy.remove_from_list("modules", "whitelist", "nonexistent")
        assert result["ok"]  # Should not error


class TestHardwarePolicy:
    """Hardware (dict-based) policy."""

    def test_add_hardware_whitelist(self, policy):
        item = {"vendor": "046d", "product": "c52b", "name": "Logitech Mouse"}
        policy.add_to_whitelist("hardware", item)
        assert policy.is_whitelisted("hardware", "Logitech Mouse")

    def test_add_hardware_blacklist(self, policy):
        item = {"vendor": "1234", "product": "5678", "name": "BadUSB"}
        policy.add_to_blacklist("hardware", item)
        assert policy.is_blacklisted("hardware", "BadUSB")


class TestPersistence:
    """YAML save/load."""

    def test_data_survives_reload(self, tmp_path):
        yaml_file = tmp_path / "persist_test.yaml"
        with patch("asset_policy.POLICY_FILE", yaml_file), \
             patch("asset_policy.POLICY_FILE_DEV", yaml_file):
            p1 = AssetPolicy()
            p1.add_to_whitelist("modules", "persist_mod")
            p1.add_to_blacklist("packages", "bad_pkg")

        # Reload
        with patch("asset_policy.POLICY_FILE", yaml_file), \
             patch("asset_policy.POLICY_FILE_DEV", yaml_file):
            p2 = AssetPolicy()
            assert p2.is_whitelisted("modules", "persist_mod")
            assert p2.is_blacklisted("packages", "bad_pkg")
