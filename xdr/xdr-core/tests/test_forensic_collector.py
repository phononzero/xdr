#!/usr/bin/env python3
"""
Tests for Forensic Collector — evidence collection, sensitivity redaction.

Module-level constants must be patched before instantiation.
"""

import os
import json
import pytest
from pathlib import Path


class TestForensicCollector:
    """Tests for ForensicCollector evidence collection."""

    def _setup(self, tmp_path):
        forensics_dir = tmp_path / "forensics"
        forensics_dir.mkdir(exist_ok=True)
        import forensic_collector as fc_mod
        fc_mod.FORENSICS_DIR = forensics_dir
        collector = fc_mod.ForensicCollector()
        return collector, forensics_dir

    def test_collect_creates_file(self, tmp_path):
        collector, forensics_dir = self._setup(tmp_path)
        alert = {
            "pid": os.getpid(),
            "reason": "TEST_ALERT",
            "mitre_id": "T1059",
            "alert_level": 3,
            "detail": "Test forensic event",
        }
        filepath = collector.collect(alert)
        assert filepath is not None
        assert os.path.isfile(filepath)
        with open(filepath) as f:
            data = json.load(f)
        assert "metadata" in data
        assert "process" in data
        assert data["metadata"]["target_pid"] == os.getpid()
        assert data["metadata"]["trigger_alert"]["reason"] == "TEST_ALERT"

    def test_collect_skips_invalid_pid(self, tmp_path):
        collector, _ = self._setup(tmp_path)
        result = collector.collect({"pid": 0, "reason": "TEST"})
        assert result is None

    def test_collect_skips_low_pid(self, tmp_path):
        collector, _ = self._setup(tmp_path)
        result = collector.collect({"pid": 1, "reason": "TEST"})
        assert result is None

    def test_evidence_contains_sha256(self, tmp_path):
        collector, _ = self._setup(tmp_path)
        alert = {"pid": os.getpid(), "reason": "TEST", "alert_level": 3}
        filepath = collector.collect(alert)
        assert filepath is not None
        with open(filepath) as f:
            data = json.load(f)
        assert "evidence_sha256" in data["metadata"]
        assert len(data["metadata"]["evidence_sha256"]) == 64

    def test_environ_redaction(self, tmp_path):
        collector, _ = self._setup(tmp_path)
        env = collector._collect_environ(os.getpid())
        for key, val in env.items():
            if any(s in key.upper() for s in ("PASSWORD", "SECRET", "TOKEN")):
                assert val == "***REDACTED***"

    def test_process_info_collection(self, tmp_path):
        collector, _ = self._setup(tmp_path)
        info = collector._collect_process_info(os.getpid())
        assert info["exists"] is True
        assert info["pid"] == os.getpid()
        assert "cmdline" in info
        assert "exe" in info

    def test_process_info_nonexistent_pid(self, tmp_path):
        collector, _ = self._setup(tmp_path)
        info = collector._collect_process_info(999999)
        assert info["exists"] is False

    def test_cleanup_old_files(self, tmp_path):
        forensics_dir = tmp_path / "forensics"
        forensics_dir.mkdir(exist_ok=True)
        for i in range(10):
            (forensics_dir / f"evidence_{i}.json").write_text("{}")

        import forensic_collector as fc_mod
        fc_mod.FORENSICS_DIR = forensics_dir
        fc_mod.MAX_FORENSIC_FILES = 5
        collector = fc_mod.ForensicCollector()
        collector._cleanup_old()
        remaining = list(forensics_dir.glob("*.json"))
        assert len(remaining) <= 5

    def test_get_stats(self, tmp_path):
        collector, _ = self._setup(tmp_path)
        stats = collector.get_stats()
        assert "total_collections" in stats
        assert "stored_evidence" in stats
        assert stats["total_collections"] == 0

    def test_parent_chain_collection(self, tmp_path):
        collector, _ = self._setup(tmp_path)
        chain = collector._collect_parent_chain(os.getpid())
        assert isinstance(chain, list)
        if chain:
            assert "pid" in chain[0]
            assert "comm" in chain[0]
