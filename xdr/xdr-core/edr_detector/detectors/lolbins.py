#!/usr/bin/env python3
"""LOLBins detection (suspicious argv patterns)."""

import os
import re
from fnmatch import fnmatch
from ..rules import LOLBIN_RULES


def check_lolbins(pid: int, comm: str, cmdline: str, path: str,
                  policy: dict, auto_block: bool, blocker) -> dict | None:
    """
    Detect Living-off-the-Land binary abuse.
    """
    if not comm or not cmdline:
        return None

    # Check whitelist
    for wl in policy.get("lolbins_whitelist", []):
        if fnmatch(comm, wl):
            return None

    for rule in LOLBIN_RULES:
        # Check comm matches
        comm_match = False
        for c in rule["comm"]:
            if fnmatch(comm, c):
                comm_match = True
                break
        if not comm_match:
            continue

        # Check argv patterns
        for argv_pat in rule["argv"]:
            try:
                if re.search(argv_pat, cmdline):
                    action = "ALERT"
                    if auto_block:
                        blocker.kill_pid(pid)
                        action = "KILL"

                    return {
                        "action": action,
                        "reason": "LOLBIN",
                        "detail": f"{rule['name']}: {rule['desc']} "
                                 f"(cmd={cmdline[:100]})",
                        "alert_level": rule["level"],
                        "pid": pid,
                        "path": path,
                        "rule": rule["name"],
                        "mitre_id": rule.get("mitre", ""),
                        "auto_blocked": action == "KILL",
                    }
            except re.error:
                pass

    return None


def scan_cmdlines(policy: dict) -> list[dict]:
    """Scan all running process cmdlines for LOLBin patterns."""
    results = []
    try:
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            pid = int(name)
            if pid <= 2:
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    raw = f.read()
                if not raw:
                    continue
                cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
                if not cmdline:
                    continue

                with open(f"/proc/{pid}/comm") as f:
                    comm = f.read().strip()

                exe = ""
                try:
                    exe = os.readlink(f"/proc/{pid}/exe")
                except OSError:
                    pass

                for rule in LOLBIN_RULES:
                    comm_match = False
                    for c in rule["comm"]:
                        if fnmatch(comm, c):
                            comm_match = True
                            break
                    if not comm_match:
                        continue

                    for argv_pat in rule["argv"]:
                        try:
                            if re.search(argv_pat, cmdline):
                                results.append({
                                    "action": "ALERT",
                                    "reason": "LOLBIN",
                                    "detail": f"{rule['name']}: {rule['desc']} "
                                             f"(cmd={cmdline[:100]})",
                                    "alert_level": rule["level"],
                                    "pid": pid,
                                    "path": exe,
                                    "rule": rule["name"],
                                    "mitre_id": rule.get("mitre", ""),
                                })
                                break
                        except re.error:
                            pass
            except (OSError, PermissionError):
                continue
    except OSError:
        pass
    return results
