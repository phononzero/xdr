"""
XDR Alert System — Desktop notification alerts with rate limiting.
"""

import os
import time
import subprocess

from .ebpf_structs import ALERT_NAMES, ALERT_WARNING, ALERT_CRITICAL


class AlertSystem:
    """Sends alerts via desktop notification with dedup/rate-limiting."""

    # Same alert title won't fire more than once per interval
    RATE_LIMIT_SECS = 5

    def __init__(self):
        self._last_sent: dict[str, float] = {}

    def send(self, level: int, title: str, message: str):
        level_name = ALERT_NAMES.get(level, "UNKNOWN")

        if level < ALERT_WARNING:
            return

        # ── Rate limit: skip duplicate within interval ──
        now = time.time()
        key = f"{level_name}:{title}"
        prev = self._last_sent.get(key, 0.0)
        if now - prev < self.RATE_LIMIT_SECS:
            return
        self._last_sent[key] = now

        # ── Clean old entries (avoid memory leak) ──
        if len(self._last_sent) > 500:
            cutoff = now - self.RATE_LIMIT_SECS * 2
            self._last_sent = {k: v for k, v in self._last_sent.items() if v > cutoff}

        # ── Desktop notification ──
        try:
            icon = "security-high" if level >= ALERT_CRITICAL else "dialog-warning"
            urgency = "critical" if level >= ALERT_CRITICAL else "normal"
            subprocess.Popen([
                "notify-send", "-u", urgency,
                "-i", icon,
                f"🛡️ XDR {level_name}", message
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            pass
