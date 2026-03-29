#!/usr/bin/env python3
"""Behavioral sequence analysis."""

import time
from fnmatch import fnmatch
from ..rules import SEQUENCE_PATTERNS


def check_sequences(pid: int, pid_events: dict) -> dict | None:
    """Check if PID's event history matches any threat sequence."""
    events = pid_events.get(pid, [])
    if len(events) < 2:
        return None

    for pattern in SEQUENCE_PATTERNS:
        window = pattern["window_secs"]
        steps = pattern["steps"]
        now = time.time()

        # Get events within window
        recent = [e for e in events if now - e["time"] < window]
        if len(recent) < len(steps):
            continue

        # Try to match steps in order
        matched = 0
        for evt in recent:
            if matched >= len(steps):
                break
            step = steps[matched]
            if evt["type"] == step["type"]:
                path_match = step.get("path_match")
                if path_match:
                    evt_path = evt.get("path", "") or evt.get("filename", "")
                    patterns = path_match.split("|")
                    if not any(fnmatch(evt_path, p) for p in patterns):
                        continue
                matched += 1

        if matched >= len(steps):
            return {
                "action": "ALERT",
                "reason": "BEHAVIOR_SEQUENCE",
                "detail": f"{pattern['name']}: {pattern['description']}",
                "alert_level": pattern["alert_level"],
                "pid": pid,
                "pattern": pattern["name"],
            }

    return None
