#!/usr/bin/env python3
"""Fileless malware detection (memfd/proc)."""

from fnmatch import fnmatch
from ..rules import MEMFD_PATTERNS


def check_memfd(pid: int, path: str, comm: str,
                auto_block: bool, blocker) -> dict | None:
    """
    Detect fileless malware: memfd_create(), /proc/*/fd/ execution.
    """
    if not path:
        return None

    for pattern in MEMFD_PATTERNS:
        if pattern.endswith("*"):
            if fnmatch(path, pattern):
                break
        elif pattern in path:
            break
    else:
        return None

    # Detected fileless execution!
    action = "ALERT"
    if auto_block:
        blocker.kill_pid(pid)
        action = "KILL"

    return {
        "action": action,
        "reason": "FILELESS_EXEC",
        "detail": f"파일리스 실행 감지: {path} (comm={comm})",
        "alert_level": 3,
        "pid": pid,
        "path": path,
        "mitre_id": "T1620",
        "auto_blocked": action == "KILL",
    }
