#!/usr/bin/env python3
"""
EDR Detector — Block engine (kill, hash, path blocking + failure logging).
"""

import os
import hashlib
import logging
from fnmatch import fnmatch


class BlockEngine:
    """Handles process killing, path/hash blocking, and failure logging."""

    def __init__(self, blocklist_store):
        self.store = blocklist_store
        self._hash_cache = {}
        self._max_cache = 5000

    def kill_pid(self, pid: int) -> bool:
        """Send SIGKILL to a process. Returns True if successful."""
        try:
            os.kill(pid, 9)
            return True
        except ProcessLookupError:
            logging.warning(f"BLOCK_FAILED: pid={pid} — process not found")
            return False
        except PermissionError:
            logging.warning(f"BLOCK_FAILED: pid={pid} — permission denied")
            return False

    def kill_and_block(self, pid: int) -> dict:
        """
        Kill PID immediately + permanently block its path and hash.
        Returns info about what was blocked.
        """
        result = {"pid": pid, "killed": False, "path": None, "sha256": None,
                  "block_failed": False, "failure_reason": ""}

        # Get process info
        path = self.get_pid_exe_path(pid)
        sha256 = None

        if path:
            sha256 = self.get_sha256(path)
            result["path"] = path
            result["sha256"] = sha256

            # Add path to permanent blocklist
            self.store.add_blocked_path(path)

            # Add hash to permanent blocklist
            if sha256:
                self.store.add_blocked_hash(sha256, os.path.basename(path),
                                             "kill_and_block")

        # Kill the process
        killed = self.kill_pid(pid)
        result["killed"] = killed

        if not killed:
            result["block_failed"] = True
            # Try to determine why
            if not os.path.exists(f"/proc/{pid}"):
                result["failure_reason"] = "PROCESS_NOT_FOUND"
            else:
                result["failure_reason"] = "PERMISSION_DENIED"

            # Push block failure event
            try:
                from api import push_event
                comm = ""
                try:
                    with open(f"/proc/{pid}/comm") as f:
                        comm = f.read().strip()
                except OSError:
                    pass
                push_event({
                    "source": "DETECTOR",
                    "action": "BLOCK_FAILED",
                    "reason": result["failure_reason"],
                    "detail": f"차단 실패: pid={pid} comm={comm} path={path or 'unknown'} "
                              f"사유={result['failure_reason']}",
                    "alert_level": 3,
                    "pid": pid,
                    "comm": comm,
                    "path": path,
                })
            except Exception as e:
                logging.error(f"Failed to push block failure event: {e}")

        return result

    def check_path_blocked(self, path: str) -> bool:
        """Check if path matches any blocked pattern."""
        blocked_paths = self.store.get("blocked_paths")
        if not blocked_paths:
            return False
        for pattern in blocked_paths:
            if fnmatch(path, pattern) or path == pattern:
                return True
        return False

    def check_hash_blocked(self, sha256: str) -> bool:
        """Check if SHA256 is in blocked hashes."""
        blocked = self.store.get("blocked_hashes")
        if not blocked:
            return False
        for entry in blocked:
            h = entry if isinstance(entry, str) else entry.get("hash", "")
            if h == sha256:
                return True
        return False

    def get_sha256(self, path: str) -> str | None:
        """Compute SHA256 of file, with caching."""
        if path in self._hash_cache:
            return self._hash_cache[path]

        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            digest = h.hexdigest()

            if len(self._hash_cache) < self._max_cache:
                self._hash_cache[path] = digest
            return digest
        except (OSError, PermissionError):
            return None

    @staticmethod
    def get_pid_exe_path(pid: int) -> str | None:
        """Get executable path of a running PID via /proc."""
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except (OSError, PermissionError):
            return None
