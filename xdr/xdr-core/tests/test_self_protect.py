#!/usr/bin/env python3
"""
Tests for Self-Protection — file tampering, deletion detection.

Module-level constants (XDR_DIR, HASH_STORE, CRITICAL_FILES) must be
patched BEFORE class instantiation, so we patch at the module attribute level.
"""

import os
import json
import pytest
from pathlib import Path
from unittest.mock import patch


class TestSelfProtect:
    """Tests for SelfProtect anti-tampering module."""

    def _setup(self, tmp_path, event_collector=None):
        """Patch module-level constants and create a SelfProtect instance."""
        xdr_dir = tmp_path / "xdr"
        core_dir = xdr_dir / "xdr-core"
        core_dir.mkdir(parents=True)
        hash_store = tmp_path / "self_protect_hashes.json"

        (core_dir / "xdr_engine.py").write_text("print('engine')")

        import self_protect as sp_mod
        sp_mod.XDR_DIR = xdr_dir
        sp_mod.HASH_STORE = hash_store
        sp_mod.CRITICAL_FILES = ["xdr-core/xdr_engine.py"]

        instance = sp_mod.SelfProtect(push_event_fn=event_collector)
        return instance, xdr_dir, hash_store

    def test_baseline_creation(self, tmp_path):
        sp, xdr_dir, hash_store = self._setup(tmp_path)
        sp._baseline()
        assert len(sp._baseline_hashes) > 0
        assert hash_store.exists()

    def test_no_tampering_clean(self, tmp_path):
        sp, xdr_dir, _ = self._setup(tmp_path)
        sp._baseline()
        alerts = sp.check_integrity()
        tamper_alerts = [a for a in alerts if a["reason"] != "XDR_PROCESS_KILLED"]
        assert len(tamper_alerts) == 0

    def test_file_modification_detected(self, tmp_path):
        sp, xdr_dir, _ = self._setup(tmp_path)
        sp._baseline()
        (xdr_dir / "xdr-core" / "xdr_engine.py").write_text("TAMPERED")
        alerts = sp.check_integrity()
        tamper_alerts = [a for a in alerts if a["reason"] == "XDR_FILE_TAMPERED"]
        assert len(tamper_alerts) > 0
        assert tamper_alerts[0]["mitre_id"] == "T1562.001"

    def test_file_deletion_detected(self, tmp_path):
        sp, xdr_dir, _ = self._setup(tmp_path)
        sp._baseline()
        (xdr_dir / "xdr-core" / "xdr_engine.py").unlink()
        alerts = sp.check_integrity()
        delete_alerts = [a for a in alerts if a["reason"] == "XDR_FILE_DELETED"]
        assert len(delete_alerts) > 0

    def test_get_stats(self, tmp_path):
        sp, _, _ = self._setup(tmp_path)
        sp._baseline()
        stats = sp.get_stats()
        assert "xdr_pid" in stats
        assert "monitored_files" in stats
        assert stats["monitored_files"] > 0

    def test_tamper_count_increments(self, tmp_path, event_collector):
        sp, xdr_dir, _ = self._setup(tmp_path, event_collector)
        sp._baseline()
        (xdr_dir / "xdr-core" / "xdr_engine.py").write_text("EVIL")
        sp.check_integrity()
        assert sp._tamper_count > 0
