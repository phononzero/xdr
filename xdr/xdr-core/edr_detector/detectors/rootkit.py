#!/usr/bin/env python3
"""Kernel rootkit detection."""

import os
import logging


def check_kernel_integrity(policy: dict, auto_block_rootkit: bool,
                           tracker) -> list[dict]:
    """
    Periodic kernel integrity checks:
    - Detect unknown kernel modules
    - Detect hidden processes
    - Detect sysctl tampering
    """
    alerts = []

    module_alert = _check_modules(policy, auto_block_rootkit)
    if module_alert:
        alerts.extend(module_alert)

    hidden_alert = _check_hidden_processes()
    if hidden_alert:
        alerts.extend(hidden_alert)

    sysctl_alert = _check_sysctl_tampering()
    if sysctl_alert:
        alerts.extend(sysctl_alert)

    return alerts


def _check_modules(policy: dict, auto_block: bool) -> list[dict]:
    """Check for unknown kernel modules."""
    alerts = []
    allowed = set(policy.get("allowed_modules", []))
    try:
        with open("/proc/modules") as f:
            for line in f:
                mod_name = line.split()[0]
                if allowed and mod_name not in allowed:
                    action = "ALERT"
                    if auto_block:
                        try:
                            import subprocess
                            subprocess.run(["rmmod", mod_name],
                                         capture_output=True, timeout=5)
                            action = "UNLOADED"
                        except Exception:
                            pass
                    alerts.append({
                        "action": action,
                        "reason": "UNKNOWN_MODULE",
                        "detail": f"미등록 커널 모듈: {mod_name}",
                        "alert_level": 3,
                        "module": mod_name,
                        "auto_blocked": action == "UNLOADED",
                    })
    except OSError:
        pass
    return alerts


def _check_hidden_processes() -> list[dict]:
    """Detect processes hidden from /proc but visible via task iteration."""
    alerts = []
    try:
        proc_pids = set()
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                proc_pids.add(int(entry))

        for pid in proc_pids:
            try:
                status_path = f"/proc/{pid}/status"
                exe_path = f"/proc/{pid}/exe"
                if os.path.exists(status_path):
                    exe = os.readlink(exe_path) if os.path.exists(exe_path) else ""
                    if exe and "(deleted)" in exe:
                        with open(status_path) as sf:
                            comm = sf.readline().split(":")[1].strip()
                        alerts.append({
                            "action": "ALERT",
                            "reason": "DELETED_BINARY",
                            "detail": f"삭제된 바이너리 실행 중: "
                                     f"pid={pid} comm={comm} exe={exe}",
                            "alert_level": 2,
                            "pid": pid,
                        })
            except (OSError, PermissionError, IndexError):
                continue
    except OSError:
        pass
    return alerts


def _check_sysctl_tampering() -> list[dict]:
    """Check critical sysctl values for tampering."""
    alerts = []
    monitor_sysctls = [
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/kernel/randomize_va_space",
    ]
    for path in monitor_sysctls:
        try:
            with open(path) as f:
                val = f.read().strip()
            if path.endswith("ip_forward") and val == "1":
                alerts.append({
                    "action": "ALERT",
                    "reason": "SYSCTL_SUSPICIOUS",
                    "detail": f"IP forwarding 활성화: {path}={val}",
                    "alert_level": 2,
                })
            if path.endswith("randomize_va_space") and val != "2":
                alerts.append({
                    "action": "ALERT",
                    "reason": "ASLR_DISABLED",
                    "detail": f"ASLR 비활성화/약화: {path}={val}",
                    "alert_level": 3,
                })
        except OSError:
            pass
    return alerts
