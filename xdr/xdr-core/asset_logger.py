#!/usr/bin/env python3
"""
XDR Asset Logger — Event recording for kernel/package/hardware changes.

Records all asset-related events as JSON Lines (.jsonl) for audit trail.
"""

import json
import time
import logging
from pathlib import Path
from threading import Lock
from datetime import datetime

logger = logging.getLogger("xdr.asset_log")

LOG_DIR = Path("/opt/xdr/logs")
LOG_FILE = LOG_DIR / "asset_events.jsonl"
LOG_FILE_DEV = Path(__file__).parent / "asset_events.jsonl"

# Event types
EVT_MODULE_LOAD = "MODULE_LOAD"
EVT_MODULE_UNLOAD = "MODULE_UNLOAD"
EVT_MODULE_BLOCK = "MODULE_BLOCK"
EVT_PACKAGE_INSTALL = "PACKAGE_INSTALL"
EVT_PACKAGE_REMOVE = "PACKAGE_REMOVE"
EVT_HW_CONNECT = "HW_CONNECT"
EVT_HW_DISCONNECT = "HW_DISCONNECT"
EVT_HW_BLOCK = "HW_BLOCK"
EVT_SCAN_RESULT = "SCAN_RESULT"
EVT_ACTION = "ACTION"
EVT_POLICY_CHANGE = "POLICY_CHANGE"

MAX_LOG_ENTRIES = 10000  # Keep last N entries


class AssetLogger:
    """Thread-safe asset event logger with JSONL persistence."""

    def __init__(self):
        self._lock = Lock()
        self._log_path = LOG_FILE if LOG_DIR.exists() else LOG_FILE_DEV
        self._ensure_dir()

    def _ensure_dir(self):
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError):
            self._log_path = LOG_FILE_DEV
            self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event_type: str, category: str, name: str,
            detail: str = "", result: str = "", extra: dict = None):
        """Record an asset event."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "epoch": time.time(),
            "event_type": event_type,
            "category": category,
            "name": name,
            "detail": detail,
            "result": result,
        }
        if extra:
            entry.update(extra)

        with self._lock:
            try:
                with open(self._log_path, "a") as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            except Exception as e:
                logger.error(f"Asset log write error: {e}")

    def get_logs(self, limit: int = 200, offset: int = 0,
                 event_type: str = None, category: str = None,
                 search: str = None) -> list[dict]:
        """Read log entries with optional filtering."""
        entries = []
        with self._lock:
            try:
                if not self._log_path.exists():
                    return []

                for line in self._log_path.read_text().strip().splitlines():
                    try:
                        entry = json.loads(line)
                        if event_type and entry.get("event_type") != event_type:
                            continue
                        if category and entry.get("category") != category:
                            continue
                        if search and search.lower() not in json.dumps(
                                entry, ensure_ascii=False).lower():
                            continue
                        entries.append(entry)
                    except json.JSONDecodeError:
                        continue
            except (FileNotFoundError, PermissionError):
                return []

        # Return newest first
        entries.reverse()
        return entries[offset:offset + limit]

    def get_stats(self) -> dict:
        """Get summary statistics."""
        stats = {"total": 0, "by_type": {}, "by_category": {}}
        with self._lock:
            try:
                if not self._log_path.exists():
                    return stats
                for line in self._log_path.read_text().strip().splitlines():
                    try:
                        entry = json.loads(line)
                        stats["total"] += 1
                        et = entry.get("event_type", "unknown")
                        cat = entry.get("category", "unknown")
                        stats["by_type"][et] = stats["by_type"].get(et, 0) + 1
                        stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
                    except json.JSONDecodeError:
                        continue
            except (FileNotFoundError, PermissionError):
                pass
        return stats

    def rotate(self):
        """Rotate log if it exceeds MAX_LOG_ENTRIES."""
        with self._lock:
            try:
                if not self._log_path.exists():
                    return
                lines = self._log_path.read_text().strip().splitlines()
                if len(lines) > MAX_LOG_ENTRIES:
                    keep = lines[-MAX_LOG_ENTRIES:]
                    self._log_path.write_text("\n".join(keep) + "\n")
                    logger.info(f"Asset log rotated: kept {len(keep)} entries")
            except Exception as e:
                logger.error(f"Log rotation error: {e}")


# Singleton
_instance = None

def get_logger() -> AssetLogger:
    global _instance
    if _instance is None:
        _instance = AssetLogger()
    return _instance
