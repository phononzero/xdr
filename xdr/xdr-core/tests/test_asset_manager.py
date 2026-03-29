#!/usr/bin/env python3
"""Tests for asset_manager — kernel modules, packages, hardware."""

import os
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import asset_manager


class TestKernelModules:
    """Kernel module listing and classification."""

    def test_get_loaded_modules_returns_list(self):
        modules = asset_manager.get_loaded_modules()
        assert isinstance(modules, list)

    def test_modules_have_required_fields(self):
        modules = asset_manager.get_loaded_modules()
        if not modules:
            pytest.skip("No modules loaded (unusual)")
        m = modules[0]
        assert "name" in m
        assert "size" in m
        assert "size_kb" in m
        assert "used_count" in m
        assert "state" in m
        assert "safety" in m
        assert "removable" in m

    def test_modules_sorted_by_name(self):
        modules = asset_manager.get_loaded_modules()
        names = [m["name"] for m in modules]
        assert names == sorted(names)

    def test_safety_classification(self):
        modules = asset_manager.get_loaded_modules()
        for m in modules:
            assert m["safety"] in ("safe", "suspicious", "unknown")

    def test_removable_only_when_unused(self):
        modules = asset_manager.get_loaded_modules()
        for m in modules:
            if m["removable"]:
                assert m["used_count"] == 0

    def test_unload_nonexistent_module(self):
        result = asset_manager.unload_module("__xdr_fake_module_999__")
        assert isinstance(result, dict)
        assert "ok" in result
        # Should fail — no such module
        assert result["ok"] is False

    def test_block_module_returns_dict(self):
        # Don't actually write — mock the file operations
        with patch("builtins.open", MagicMock()):
            with patch.object(Path, "exists", return_value=True):
                with patch.object(Path, "read_text", return_value=""):
                    result = asset_manager.block_module("test_fake_mod")
                    assert isinstance(result, dict)
                    assert "ok" in result


class TestPackages:
    """Package listing."""

    def test_get_installed_packages_returns_list(self):
        packages = asset_manager.get_installed_packages()
        assert isinstance(packages, list)

    def test_packages_have_name_and_version(self):
        packages = asset_manager.get_installed_packages()
        if not packages:
            pytest.skip("No packages found (non-dpkg system?)")
        p = packages[0]
        assert "name" in p
        assert "version" in p

    def test_package_count_reasonable(self):
        packages = asset_manager.get_installed_packages()
        # Any Linux system should have 100+ packages
        if packages:
            assert len(packages) > 50


class TestHardware:
    """Hardware device listing."""

    def test_get_hardware_devices_returns_list(self):
        devices = asset_manager.get_hardware_devices()
        assert isinstance(devices, list)

    def test_devices_have_type_field(self):
        devices = asset_manager.get_hardware_devices()
        for d in devices:
            assert "type" in d
            assert d["type"] in ("usb", "pci", "input")

    def test_input_devices_from_proc(self):
        devices = asset_manager._get_input_devices()
        assert isinstance(devices, list)
        # Should have at least keyboard
        if devices:
            assert any("name" in d for d in devices)

    def test_block_usb_invalid(self):
        # Mock filesystem
        with patch("builtins.open", MagicMock()):
            with patch.object(Path, "exists", return_value=False):
                with patch("subprocess.run", MagicMock()):
                    result = asset_manager.block_usb_device("0000", "0000")
                    assert isinstance(result, dict)


class TestHelpers:
    """Internal helper functions."""

    def test_builtin_set_returns_set(self):
        kernel_ver = os.uname().release
        builtins = asset_manager._get_builtin_set(kernel_ver)
        assert isinstance(builtins, set)

    def test_system_module_set(self):
        kernel_ver = os.uname().release
        mods = asset_manager._get_system_module_set(kernel_ver)
        assert isinstance(mods, set)
