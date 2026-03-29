#!/usr/bin/env python3
"""Ptrace injection monitoring."""

import time
from fnmatch import fnmatch


def check_ptrace(event: dict, policy: dict, tracker,
                 auto_block: bool, blocker, ptrace_events: dict) -> dict | None:
    """
    Monitor ptrace syscalls for process injection.
    """
    tracer_pid = event.get("pid", 0)
    target_pid = event.get("target_pid", 0)
    tracer_comm = event.get("comm", "")
    ptrace_req = event.get("ptrace_request", 0)

    # PTRACE_ATTACH=16, PTRACE_SEIZE=0x4206,
    # PTRACE_POKETEXT=4, PTRACE_POKEDATA=5
    DANGEROUS_REQUESTS = {4, 5, 16, 0x4206}

    if ptrace_req not in DANGEROUS_REQUESTS:
        return None

    # Check whitelist
    for wl in policy.get("ptrace_whitelist", []):
        if fnmatch(tracer_comm, wl):
            return None

    # Check if tracer is parent of target (normal)
    target_proc = tracker.get_process(target_pid)
    if target_proc and target_proc.ppid == tracer_pid:
        return None  # Parent tracing child — normal

    # Non-parent ptrace — suspicious!
    ptrace_events[target_pid] = {
        "tracer_pid": tracer_pid,
        "tracer_comm": tracer_comm,
        "time": time.time(),
    }

    action = "ALERT"
    if auto_block:
        blocker.kill_pid(tracer_pid)
        action = "KILL"

    return {
        "action": action,
        "reason": "PTRACE_INJECTION",
        "detail": f"비부모 ptrace 감지: {tracer_comm}(pid={tracer_pid}) → "
                 f"target(pid={target_pid}) req={ptrace_req}",
        "alert_level": 3,
        "pid": tracer_pid,
        "target_pid": target_pid,
        "auto_blocked": action == "KILL",
    }
