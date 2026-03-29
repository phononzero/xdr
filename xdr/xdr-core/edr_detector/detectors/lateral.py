#!/usr/bin/env python3
"""Lateral movement + network scan detection."""

import time


def check_lateral_movement(event: dict, policy: dict,
                           ip_connect_log: dict,
                           auto_block: bool, blocker) -> dict | None:
    """
    Detect lateral movement:
    - Internal network port scanning
    - SSH connections to internal IPs
    - SMB/WinRM connections
    """
    pid = event.get("pid", 0)
    comm = event.get("comm", "")
    dst_ip = event.get("dst_ip", "")
    dst_port = event.get("dst_port", 0)

    if not dst_ip:
        return None

    if not _is_internal_ip(dst_ip):
        return None

    # Check whitelist
    for wl in policy.get("lateral_whitelist", []):
        if dst_ip == wl:
            return None

    # Track internal connections for scan detection
    now = time.time()
    scan_key = f"scan:{pid}"
    if scan_key not in ip_connect_log:
        ip_connect_log[scan_key] = []
    ip_connect_log[scan_key].append({
        "time": now, "ip": dst_ip, "port": dst_port
    })

    # Keep last 60 seconds
    ip_connect_log[scan_key] = [
        e for e in ip_connect_log[scan_key]
        if now - e["time"] < 60
    ]
    recent = ip_connect_log[scan_key]

    # Port scan detection: many different ports in short time
    unique_ports = len(set(e["port"] for e in recent))
    threshold = policy.get("scan_threshold", 20)
    if unique_ports >= threshold:
        action = "ALERT"
        if auto_block:
            blocker.kill_pid(pid)
            action = "KILL"
        return {
            "action": action,
            "reason": "PORT_SCAN",
            "detail": f"내부 포트 스캔 감지: {comm}(pid={pid}) → "
                     f"{dst_ip} ({unique_ports}개 포트/60초)",
            "alert_level": 3,
            "pid": pid,
            "dst_ip": dst_ip,
            "unique_ports": unique_ports,
            "auto_blocked": action == "KILL",
        }

    # SSH to internal host
    if dst_port == 22:
        unique_ips = len(set(e["ip"] for e in recent
                           if e["port"] == 22))
        if unique_ips >= 3:
            return {
                "action": "ALERT",
                "reason": "SSH_LATERAL",
                "detail": f"내부 SSH 다중 접속: {comm}(pid={pid}) → "
                         f"{unique_ips}개 내부 호스트",
                "alert_level": 3,
                "pid": pid,
                "unique_hosts": unique_ips,
            }

    # SMB (445) / WinRM (5985/5986) to internal
    if dst_port in (445, 5985, 5986):
        return {
            "action": "ALERT",
            "reason": "SMB_LATERAL",
            "detail": f"내부 SMB/WinRM 연결: {comm}(pid={pid}) → "
                     f"{dst_ip}:{dst_port}",
            "alert_level": 2,
            "pid": pid,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
        }

    return None


def _is_internal_ip(ip: str) -> bool:
    """Check if IP is an internal/private address."""
    if not ip or ip in ("0.0.0.0", "::", "127.0.0.1"):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        return (a == 10 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168))
    except ValueError:
        return False
