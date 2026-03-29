#!/usr/bin/env python3
"""
XDR Test Suite — Shared fixtures for pytest.

Provides mock objects so tests can run without eBPF, root privileges,
or /opt/xdr filesystem.
"""

import os
import sys
import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure xdr-core is importable
XDR_CORE_DIR = Path(__file__).resolve().parent.parent
if str(XDR_CORE_DIR) not in sys.path:
    sys.path.insert(0, str(XDR_CORE_DIR))

# ── Pre-import patches ───────────────────────────────────
# api.middleware calls _get_api_secret() at module load (line 29).
# We must make SECRET_FILE readable BEFORE that import happens.
# Approach: temporarily create the file if needed.
_secret_path = Path("/opt/xdr/xdr-core/.api_secret")
_created_secret = False
try:
    if not _secret_path.exists():
        _secret_path.parent.mkdir(parents=True, exist_ok=True)
        _secret_path.write_text("test_secret_for_pytest")
        _secret_path.chmod(0o600)
        _created_secret = True
except PermissionError:
    # Can't write to /opt/xdr — use monkeypatch approach instead:
    # Override _get_api_secret before module loads
    pass

# If we couldn't create the secret file, patch the module after import
try:
    import api.middleware as _mw
    _mw.API_SECRET = "test_secret_key_for_pytest"
except (PermissionError, OSError):
    # Module import failed — we'll skip API tests gracefully
    pass




# ── Mock BlocklistStore ──────────────────────────────────

class MockBlocklistStore:
    """In-memory blocklist store for testing (no disk/bpftool)."""

    def __init__(self):
        self._data = {
            "blocked_ips": [],
            "blocked_ports": [],
            "blocked_pids": [],
            "edr_watch_ips": [],
            "known_macs": {},
            "blocked_paths": [],
            "blocked_hashes": [],
        }

    def get_all(self):
        return dict(self._data)

    def get(self, list_type):
        return self._data.get(list_type, [])

    def add_blocked_ip(self, ip):
        if ip not in self._data["blocked_ips"]:
            self._data["blocked_ips"].append(ip)
            return True
        return False

    def remove_blocked_ip(self, ip):
        if ip in self._data["blocked_ips"]:
            self._data["blocked_ips"].remove(ip)
            return True
        return False

    def add_blocked_path(self, path):
        if path not in self._data["blocked_paths"]:
            self._data["blocked_paths"].append(path)
            return True
        return False

    def remove_blocked_path(self, path):
        if path in self._data["blocked_paths"]:
            self._data["blocked_paths"].remove(path)
            return True
        return False

    def add_blocked_hash(self, sha256, name="", reason=""):
        for entry in self._data["blocked_hashes"]:
            if entry.get("hash") == sha256:
                return False
        self._data["blocked_hashes"].append(
            {"hash": sha256, "name": name, "reason": reason}
        )
        return True

    def remove_blocked_hash(self, sha256):
        before = len(self._data["blocked_hashes"])
        self._data["blocked_hashes"] = [
            e for e in self._data["blocked_hashes"] if e.get("hash") != sha256
        ]
        return len(self._data["blocked_hashes"]) < before

    def add_blocked_pid(self, pid):
        if pid not in self._data["blocked_pids"]:
            self._data["blocked_pids"].append(pid)
            return True
        return False

    def sync_to_bpf(self):
        pass


@pytest.fixture
def mock_store():
    """Provide a fresh MockBlocklistStore."""
    return MockBlocklistStore()


# ── Event collector ──────────────────────────────────────

@pytest.fixture
def event_collector():
    """Provide a list-based push_event function to capture events."""
    events = []
    def push_event(evt):
        events.append(evt)
    push_event.events = events
    return push_event


# ── Temp directories ─────────────────────────────────────

@pytest.fixture
def tmp_xdr_dir(tmp_path):
    """Create a temporary /opt/xdr-like directory structure."""
    dirs = [
        tmp_path / "config",
        tmp_path / "forensics",
        tmp_path / "integrity" / "baselines",
        tmp_path / "integrity" / "diffs",
        tmp_path / "dns",
        tmp_path / "threat_intel",
        tmp_path / "xdr-core",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    return tmp_path


# ── Mock AlertSystem ─────────────────────────────────────

@pytest.fixture
def mock_alert_system():
    """AlertSystem that captures calls instead of sending notifications."""
    alert = MagicMock()
    alert.sent = []

    def capture_send(level, title, message):
        alert.sent.append({"level": level, "title": title, "message": message})

    alert.send = capture_send
    return alert


# ── Mock LogManager ──────────────────────────────────────

@pytest.fixture
def mock_log_manager():
    """LogManager that captures writes."""
    log = MagicMock()
    log.general = []
    log.critical = []

    def write_general(msg):
        log.general.append(msg)

    def write_critical(msg):
        log.critical.append(msg)

    log.write_general = write_general
    log.write_critical = write_critical
    return log
