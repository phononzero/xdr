#!/usr/bin/env python3
"""Tests for asset_logger — JSONL event logging."""

import sys
import json
import pytest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from asset_logger import AssetLogger, EVT_ACTION, EVT_SCAN_RESULT, EVT_MODULE_LOAD


@pytest.fixture
def logger(tmp_path):
    """Create an AssetLogger with temp log file."""
    log_file = tmp_path / "test_events.jsonl"
    with patch("asset_logger.LOG_FILE", log_file), \
         patch("asset_logger.LOG_FILE_DEV", log_file), \
         patch("asset_logger.LOG_DIR", tmp_path):
        lg = AssetLogger()
        lg._log_path = log_file
        yield lg


class TestLogging:
    """Event recording."""

    def test_log_creates_entry(self, logger):
        logger.log(EVT_ACTION, "modules", "test_mod", detail="test detail")
        logs = logger.get_logs()
        assert len(logs) == 1
        assert logs[0]["name"] == "test_mod"

    def test_log_has_timestamp(self, logger):
        logger.log(EVT_MODULE_LOAD, "modules", "nvidia")
        logs = logger.get_logs()
        assert "timestamp" in logs[0]
        assert "epoch" in logs[0]

    def test_log_multiple_entries(self, logger):
        for i in range(10):
            logger.log(EVT_ACTION, "modules", f"mod_{i}")
        logs = logger.get_logs()
        assert len(logs) == 10

    def test_newest_first(self, logger):
        logger.log(EVT_ACTION, "modules", "first")
        logger.log(EVT_ACTION, "modules", "second")
        logs = logger.get_logs()
        assert logs[0]["name"] == "second"
        assert logs[1]["name"] == "first"

    def test_extra_fields(self, logger):
        logger.log(EVT_SCAN_RESULT, "system", "scan",
                   extra={"summary": {"total": 5}})
        logs = logger.get_logs()
        assert logs[0]["summary"]["total"] == 5


class TestFiltering:
    """Log filtering."""

    def test_filter_by_event_type(self, logger):
        logger.log(EVT_ACTION, "modules", "action_item")
        logger.log(EVT_SCAN_RESULT, "system", "scan_item")
        logs = logger.get_logs(event_type=EVT_ACTION)
        assert len(logs) == 1
        assert logs[0]["event_type"] == EVT_ACTION

    def test_filter_by_category(self, logger):
        logger.log(EVT_ACTION, "modules", "mod_item")
        logger.log(EVT_ACTION, "hardware", "hw_item")
        logs = logger.get_logs(category="hardware")
        assert len(logs) == 1
        assert logs[0]["category"] == "hardware"

    def test_search(self, logger):
        logger.log(EVT_ACTION, "modules", "nvidia_driver")
        logger.log(EVT_ACTION, "modules", "r8169")
        logs = logger.get_logs(search="nvidia")
        assert len(logs) == 1

    def test_limit_and_offset(self, logger):
        for i in range(20):
            logger.log(EVT_ACTION, "modules", f"mod_{i}")
        logs = logger.get_logs(limit=5, offset=0)
        assert len(logs) == 5
        logs2 = logger.get_logs(limit=5, offset=5)
        assert len(logs2) == 5
        assert logs[0]["name"] != logs2[0]["name"]


class TestStats:
    """Stats and rotation."""

    def test_stats(self, logger):
        logger.log(EVT_ACTION, "modules", "mod1")
        logger.log(EVT_SCAN_RESULT, "system", "scan1")
        stats = logger.get_stats()
        assert stats["total"] == 2
        assert stats["by_type"][EVT_ACTION] == 1
        assert stats["by_type"][EVT_SCAN_RESULT] == 1

    def test_rotation(self, logger, tmp_path):
        # Write more than MAX entries
        with patch("asset_logger.MAX_LOG_ENTRIES", 10):
            for i in range(20):
                logger.log(EVT_ACTION, "modules", f"mod_{i}")
            logger.rotate()
            logs = logger.get_logs(limit=100)
            assert len(logs) == 10

    def test_empty_stats(self, logger):
        stats = logger.get_stats()
        assert stats["total"] == 0
