#!/usr/bin/env python3
"""
Tests for Integrity Monitor — baseline, scan, diff computation.

Module-level constants must be patched before instantiation.
"""

import os
import json
import pytest
from pathlib import Path


class TestIntegrityMonitor:
    """Tests for IntegrityMonitor baseline and scan logic."""

    def _setup(self, tmp_path, event_collector=None):
        integrity_dir = tmp_path / "integrity"
        baselines_dir = integrity_dir / "baselines"
        diffs_dir = integrity_dir / "diffs"
        config_file = integrity_dir / "config.json"
        current_link = integrity_dir / "current.json"

        for d in (baselines_dir, diffs_dir):
            d.mkdir(parents=True, exist_ok=True)

        # Create test files to monitor
        watch_dir = tmp_path / "watched"
        watch_dir.mkdir(exist_ok=True)
        (watch_dir / "binary1").write_bytes(b"original content 1")
        (watch_dir / "binary2").write_bytes(b"original content 2")

        import integrity_monitor as im_mod
        im_mod.INTEGRITY_DIR = integrity_dir
        im_mod.BASELINES_DIR = baselines_dir
        im_mod.DIFFS_DIR = diffs_dir
        im_mod.CONFIG_FILE = config_file
        im_mod.CURRENT_LINK = current_link
        im_mod.DEFAULT_CONFIG = {
            "scan_interval_seconds": 3600,
            "watch_paths": [
                str(watch_dir / "binary1"),
                str(watch_dir / "binary2"),
            ],
            "watch_dirs": [],
            "watch_globs": [],
        }

        monitor = im_mod.IntegrityMonitor(push_event_fn=event_collector)
        return monitor, watch_dir

    def test_initialize_baseline(self, tmp_path):
        monitor, _ = self._setup(tmp_path)
        result = monitor.initialize_baseline()
        assert result["version"] == 1
        assert result["file_count"] >= 2

    def test_scan_clean(self, tmp_path):
        monitor, _ = self._setup(tmp_path)
        monitor.initialize_baseline()
        result = monitor.run_scan()
        assert result["status"] == "clean"

    def test_scan_detect_modification(self, tmp_path, event_collector):
        monitor, watch_dir = self._setup(tmp_path, event_collector)
        monitor.initialize_baseline()
        (watch_dir / "binary1").write_bytes(b"TAMPERED CONTENT")
        result = monitor.run_scan()
        assert result["status"] == "changed"
        assert result["modified"] >= 1

    def test_scan_detect_deletion(self, tmp_path, event_collector):
        monitor, watch_dir = self._setup(tmp_path, event_collector)
        monitor.initialize_baseline()
        (watch_dir / "binary2").unlink()
        result = monitor.run_scan()
        assert result["status"] == "changed"
        assert result["removed"] >= 1

    def test_scan_detect_addition(self, tmp_path):
        monitor, watch_dir = self._setup(tmp_path)
        monitor.initialize_baseline()
        (watch_dir / "binary1").write_bytes(b"updated content new")
        result = monitor.run_scan()
        assert result["status"] == "changed"

    def test_compute_diff(self, tmp_path):
        monitor, _ = self._setup(tmp_path)
        old = {
            "/a": {"sha256": "aaa"},
            "/b": {"sha256": "bbb"},
            "/c": {"sha256": "ccc"},
        }
        new = {
            "/a": {"sha256": "aaa"},
            "/b": {"sha256": "xxx"},
            "/d": {"sha256": "ddd"},
        }
        diff = monitor._compute_diff(old, new)
        assert "/b" in diff["modified"]
        assert "/d" in diff["added"]
        assert "/c" in diff["removed"]
        assert "/a" not in diff["modified"]

    def test_get_status(self, tmp_path):
        monitor, _ = self._setup(tmp_path)
        status = monitor.get_status()
        assert status["current_version"] == 0
        monitor.initialize_baseline()
        status = monitor.get_status()
        assert status["current_version"] == 1
