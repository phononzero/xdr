#!/usr/bin/env python3
"""C2C Beacon detection."""

import time


def check_beacon(pid: int, dst_ip: str, event: dict,
                 ip_connect_log: dict) -> dict | None:
    """Detect C2C beaconing: repeated connections to same external IP."""
    now = time.time()
    ip_connect_log[dst_ip].append(now)

    # Keep only last 10 minutes
    cutoff = now - 600
    ip_connect_log[dst_ip] = [
        t for t in ip_connect_log[dst_ip] if t > cutoff
    ]

    count = len(ip_connect_log[dst_ip])
    if count >= 10:
        comm = event.get("comm", "")
        return {
            "action": "ALERT",
            "reason": "C2C_BEACON",
            "detail": f"비콘 의심: {dst_ip}에 {count}회 연결 "
                     f"(600초 내, pid={pid} comm={comm})",
            "alert_level": 3,
            "pid": pid,
            "dst_ip": dst_ip,
            "count": count,
        }
    return None
