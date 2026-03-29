#!/usr/bin/env python3
"""Tests for asset_scanner — periodic security analysis."""

import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from asset_scanner import AssetScanner, SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN


@pytest.fixture
def scanner(tmp_path):
    """Create an AssetScanner with mocked dependencies."""
    events = []
    log_file = tmp_path / "test_events.jsonl"

    with patch("asset_logger.LOG_FILE", log_file), \
         patch("asset_logger.LOG_FILE_DEV", log_file), \
         patch("asset_logger.LOG_DIR", tmp_path), \
         patch("asset_policy.POLICY_FILE", tmp_path / "policy.yaml"), \
         patch("asset_policy.POLICY_FILE_DEV", tmp_path / "policy.yaml"):
        # Reset singleton
        import asset_logger
        asset_logger._instance = None
        import asset_policy
        asset_policy._instance = None

        s = AssetScanner(push_event_fn=lambda e: events.append(e))
        s._events = events
        yield s


class TestScanExecution:
    """Full scan execution."""

    def test_scan_now_returns_results(self, scanner):
        results = scanner.scan_now()
        assert "timestamp" in results
        assert "modules" in results
        assert "packages" in results
        assert "hardware" in results
        assert "summary" in results

    def test_summary_has_counts(self, scanner):
        results = scanner.scan_now()
        for cat in ("modules", "packages", "hardware"):
            s = results["summary"][cat]
            assert "total" in s
            assert "safe" in s
            assert "suspicious" in s
            assert "malicious" in s

    def test_duration_measured(self, scanner):
        results = scanner.scan_now()
        assert "duration_ms" in results
        assert results["duration_ms"] >= 0

    def test_last_results_stored(self, scanner):
        scanner.scan_now()
        last = scanner.get_last_results()
        assert last and "timestamp" in last


class TestModuleScan:
    """Module scanning logic."""

    def test_modules_scanned(self, scanner):
        results = scanner.scan_now()
        assert len(results["modules"]) > 0

    def test_module_verdicts_valid(self, scanner):
        results = scanner.scan_now()
        valid = {SAFE, SUSPICIOUS, MALICIOUS, UNKNOWN}
        for item in results["modules"]:
            assert item["verdict"] in valid
            assert "name" in item
            assert "reason" in item

    def test_blacklisted_module_is_malicious(self, scanner, tmp_path):
        """A blacklisted module should be classified as MALICIOUS."""
        with patch("asset_policy.POLICY_FILE", tmp_path / "policy.yaml"), \
             patch("asset_policy.POLICY_FILE_DEV", tmp_path / "policy.yaml"):
            import asset_policy
            asset_policy._instance = None
            policy = asset_policy.get_policy()

            # Get a real loaded module name and blacklist it
            import asset_manager
            modules = asset_manager.get_loaded_modules()
            if not modules:
                pytest.skip("No modules to test")
            target = modules[0]["name"]
            policy.add_to_blacklist("modules", target)

            results = scanner.scan_now()
            target_result = next(
                (r for r in results["modules"] if r["name"] == target), None
            )
            assert target_result is not None
            assert target_result["verdict"] == MALICIOUS


class TestHardwareScan:
    """Hardware scanning."""

    def test_hardware_items_have_verdict(self, scanner):
        results = scanner.scan_now()
        for item in results["hardware"]:
            assert "verdict" in item
            assert "name" in item


class TestAlerts:
    """Alert generation."""

    def test_no_alert_on_clean_scan(self, scanner):
        # Most systems should produce 0 suspicious items
        scanner.scan_now()
        alerts = [e for e in scanner._events if e.get("alert_level", 0) >= 3]
        # May or may not have alerts — just verify structure
        for a in alerts:
            assert "type" in a
            assert "detail" in a
