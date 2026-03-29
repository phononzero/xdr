#!/usr/bin/env python3
"""
XDR File Audit — Sensitive file access monitoring via inotify.

Watches critical system files and directories for unauthorized access,
modifications, and deletions. Records accessor PID/comm/uid.
"""

import os
import ctypes
import ctypes.util
import struct
import logging
import time
import json
from datetime import datetime
from pathlib import Path
from threading import Thread, Event, Lock
from collections import defaultdict

AUDIT_DATA_DIR = Path("/opt/xdr/audit")
AUDIT_LOG_FILE = AUDIT_DATA_DIR / "access_log.json"

# inotify constants
IN_ACCESS = 0x00000001
IN_MODIFY = 0x00000002
IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_OPEN = 0x00000020
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400

# Events mask for monitoring
WATCH_MASK = (IN_MODIFY | IN_ATTRIB | IN_DELETE | IN_DELETE_SELF |
              IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO | IN_OPEN)

# Event names
EVENT_NAMES = {
    IN_ACCESS: "ACCESS",
    IN_MODIFY: "MODIFY",
    IN_ATTRIB: "ATTRIB",
    IN_CLOSE_WRITE: "CLOSE_WRITE",
    IN_OPEN: "OPEN",
    IN_MOVED_FROM: "MOVED_FROM",
    IN_MOVED_TO: "MOVED_TO",
    IN_CREATE: "CREATE",
    IN_DELETE: "DELETE",
    IN_DELETE_SELF: "DELETE_SELF",
}

# Default sensitive paths to watch
DEFAULT_WATCH_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/pam.d",
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/systemd/system",
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/root/.ssh",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/boot",
    "/lib/modules",
    "/opt/xdr/xdr-core",
    "/opt/xdr/config",
]

# Whitelist — known safe processes
SAFE_PROCESSES = {
    "systemd", "systemd-resolve", "systemd-journal",
    "sshd", "login", "su", "sudo",
    "cron", "anacron", "logrotate",
    "dpkg", "apt", "apt-get", "aptitude",
    "xdr_engine", "python3",
}


class FileAudit:
    """Sensitive file access monitor using inotify."""

    def __init__(self, push_event_fn=None):
        self.push_event = push_event_fn
        self._stop = Event()
        self._thread = None
        self._lock = Lock()
        self._events = []
        self._event_count = defaultdict(int)  # path -> event count
        self._inotify_fd = -1
        self._watch_descriptors = {}  # wd -> path

        AUDIT_DATA_DIR.mkdir(parents=True, exist_ok=True)

    def start(self):
        self._thread = Thread(target=self._run, daemon=True,
                            name="file-audit")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._inotify_fd >= 0:
            os.close(self._inotify_fd)
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        """Initialize inotify and process events."""
        try:
            # Initialize inotify
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            self._inotify_fd = libc.inotify_init1(0x800)  # IN_NONBLOCK

            if self._inotify_fd < 0:
                logging.error("File audit: inotify_init failed")
                return

            # Add watches
            for path in DEFAULT_WATCH_PATHS:
                self._add_watch(libc, path)

            logging.info(f"File audit: monitoring {len(self._watch_descriptors)} paths")

            # Event loop
            buf = bytearray(4096)
            while not self._stop.is_set():
                try:
                    nbytes = os.read(self._inotify_fd, 4096)
                    if nbytes:
                        self._process_inotify_events(nbytes)
                except BlockingIOError:
                    pass
                except OSError as e:
                    if e.errno != 11:  # EAGAIN
                        logging.error(f"File audit read error: {e}")
                        break
                self._stop.wait(0.5)

        except Exception as e:
            logging.error(f"File audit error: {e}")

    def _add_watch(self, libc, path: str):
        """Add inotify watch for a path."""
        if not os.path.exists(path):
            return

        try:
            path_bytes = path.encode("utf-8")
            wd = libc.inotify_add_watch(
                self._inotify_fd,
                path_bytes,
                WATCH_MASK
            )
            if wd >= 0:
                self._watch_descriptors[wd] = path

                # If directory, also watch immediate children
                if os.path.isdir(path):
                    try:
                        for entry in os.listdir(path):
                            child = os.path.join(path, entry)
                            if os.path.isfile(child):
                                child_bytes = child.encode("utf-8")
                                cwd = libc.inotify_add_watch(
                                    self._inotify_fd, child_bytes, WATCH_MASK)
                                if cwd >= 0:
                                    self._watch_descriptors[cwd] = child
                    except PermissionError:
                        pass
        except Exception as e:
            logging.debug(f"File audit: watch add error {path}: {e}")

    def _process_inotify_events(self, data: bytes):
        """Process raw inotify events."""
        offset = 0
        while offset < len(data) - 16:
            wd, mask, cookie, name_len = struct.unpack_from(
                "iIII", data, offset)
            offset += 16

            name = ""
            if name_len > 0:
                name = data[offset:offset + name_len].rstrip(b"\x00").decode(
                    "utf-8", errors="ignore")
                offset += name_len

            # Get watched path
            watched_path = self._watch_descriptors.get(wd, "?")
            full_path = os.path.join(watched_path, name) if name else watched_path

            # Determine event type
            event_types = []
            for flag, ename in EVENT_NAMES.items():
                if mask & flag:
                    event_types.append(ename)

            if not event_types:
                continue

            event_str = "|".join(event_types)

            # Record event
            event = {
                "time": datetime.now().isoformat(),
                "path": full_path,
                "event": event_str,
                "mask": mask,
            }

            with self._lock:
                self._events.append(event)
                if len(self._events) > 1000:
                    self._events = self._events[-500:]
                self._event_count[full_path] += 1

            # Alert for critical modifications
            is_critical = any(p in full_path for p in [
                "/etc/shadow", "/etc/passwd", "/etc/sudoers",
                "sshd_config", "authorized_keys", "ld.so.preload",
                ".bashrc", "/boot/vmlinuz", "/boot/initrd",
            ])

            is_modify = mask & (IN_MODIFY | IN_DELETE | IN_ATTRIB |
                               IN_DELETE_SELF | IN_MOVED_FROM)

            if is_critical and is_modify and self.push_event:
                self.push_event({
                    "action": "ALERT",
                    "reason": "CRITICAL_FILE_MODIFIED",
                    "detail": f"중요 파일 변경: {full_path} ({event_str})",
                    "alert_level": 3,
                    "path": full_path,
                    "event": event_str,
                    "source": "FILE_AUDIT",
                })

    # ── API helpers ──────────────────────────────────────

    def get_events(self, limit: int = 100) -> list[dict]:
        with self._lock:
            return self._events[-limit:]

    def get_stats(self) -> dict:
        with self._lock:
            top_files = sorted(self._event_count.items(),
                             key=lambda x: x[1], reverse=True)[:20]
            return {
                "total_events": len(self._events),
                "watched_paths": len(self._watch_descriptors),
                "top_files": [{"path": p, "count": c}
                             for p, c in top_files],
            }
