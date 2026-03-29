#!/usr/bin/env python3
"""SSL/TLS plaintext content inspection."""

import re


def check_ssl_content(event: dict) -> dict | None:
    """
    Analyze SSL/TLS plaintext captured by eBPF uprobe.
    Called when ssl_probe captures SSL_write/SSL_read data.
    """
    pid = event.get("pid", 0)
    comm = event.get("comm", "")
    data = event.get("data", b"")
    direction = event.get("direction", "")  # "write" or "read"

    if not data:
        return None

    # Convert bytes to string for pattern matching
    try:
        text = data.decode("utf-8", errors="ignore")
    except Exception:
        text = str(data)

    # Suspicious patterns in TLS-encrypted traffic
    suspicious_patterns = [
        (r"(^|\s)(id|whoami|uname|cat /etc/passwd)", "recon_cmd",
         "정찰 명령어"),
        (r"(bash|sh|cmd)\s+-[ic]", "remote_shell",
         "원격 쉘 명령"),
        (r"(wget|curl)\s+http", "c2c_download",
         "C2C 다운로드"),
        (r"(POST|PUT).*(upload|exfil|beacon)", "data_exfil",
         "데이터 유출"),
        (r"(EHLO|HELO|MAIL FROM)", "smtp_tunnel",
         "SMTP 터널링"),
        (r"(SELECT|INSERT|UPDATE|DROP)\s+", "sql_inject",
         "SQL 인젝션"),
    ]

    for pattern, name, desc in suspicious_patterns:
        try:
            if re.search(pattern, text, re.IGNORECASE):
                return {
                    "action": "ALERT",
                    "reason": "TLS_SUSPICIOUS_CONTENT",
                    "detail": f"TLS 평문 의심 내용: {desc} "
                             f"({direction}, pid={pid} comm={comm})",
                    "alert_level": 3,
                    "pid": pid,
                    "rule": name,
                    "direction": direction,
                    "snippet": text[:200],
                }
        except re.error:
            pass

    return None
