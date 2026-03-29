#!/usr/bin/env python3
"""
XDR Desktop Notification Utility.

Sends desktop notifications to the logged-in user via notify-send.
Dynamically discovers the D-Bus session bus since XDR runs as root
but needs to reach the user's desktop session.

Usage:
    from desktop_notify import send_notification
    send_notification("Title", "Message body", urgency="critical")
"""

import os
import re
import logging
import subprocess
from pathlib import Path
from functools import lru_cache

logger = logging.getLogger("xdr.notify")

# Urgency levels matching notify-send
URGENCY_LOW = "low"
URGENCY_NORMAL = "normal"
URGENCY_CRITICAL = "critical"

# XDR alert level → urgency mapping
ALERT_URGENCY = {
    1: URGENCY_LOW,       # INFO
    2: URGENCY_NORMAL,    # WARNING
    3: URGENCY_CRITICAL,  # CRITICAL
}

# Icon mapping
ALERT_ICONS = {
    1: "dialog-information",
    2: "dialog-warning",
    3: "dialog-error",
}


def _find_display_user() -> tuple[str, int]:
    """Find the user who owns the graphical session.

    Returns (username, uid).
    """
    # Method 1: Check loginctl for graphical sessions
    try:
        result = subprocess.run(
            ["loginctl", "list-sessions", "--no-legend"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 3:
                session_id = parts[0]
                uid = int(parts[1])
                user = parts[2]
                # Check if this session is graphical
                sess_info = subprocess.run(
                    ["loginctl", "show-session", session_id,
                     "--property=Type"],
                    capture_output=True, text=True, timeout=5
                )
                if "x11" in sess_info.stdout.lower() or \
                   "wayland" in sess_info.stdout.lower():
                    return user, uid
    except Exception:
        pass

    # Method 2: Check who owns DISPLAY :0
    try:
        result = subprocess.run(
            ["who"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if ":0" in line or "tty" in line:
                user = line.split()[0]
                import pwd
                pw = pwd.getpwnam(user)
                return user, pw.pw_uid
    except Exception:
        pass

    # Method 3: Fallback — find first non-root user with a desktop process
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        try:
            comm = (proc_dir / "comm").read_text().strip()
            if comm in ("mate-session", "gnome-session", "xfce4-session",
                        "plasmashell", "cinnamon-sessio"):
                stat = (proc_dir / "status").read_text()
                for line in stat.splitlines():
                    if line.startswith("Uid:"):
                        uid = int(line.split()[1])
                        if uid >= 1000:
                            import pwd
                            return pwd.getpwuid(uid).pw_name, uid
        except (PermissionError, FileNotFoundError, OSError):
            continue

    return "", 0


def _find_dbus_address(target_user: str = "", target_uid: int = 0) \
        -> str:
    """Discover the D-Bus session bus address for the desktop user."""

    if not target_user and not target_uid:
        target_user, target_uid = _find_display_user()
        if not target_user:
            return ""

    # Method 1: Read from a desktop process's environment
    desktop_procs = [
        "mate-session", "mate-panel", "gnome-session",
        "gnome-shell", "xfce4-session", "plasmashell",
        "cinnamon-sessio", "dbus-daemon",
    ]

    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        try:
            stat = (proc_dir / "status").read_text()
            uid_line = [l for l in stat.splitlines()
                        if l.startswith("Uid:")]
            if not uid_line:
                continue
            proc_uid = int(uid_line[0].split()[1])
            if proc_uid != target_uid:
                continue

            comm = (proc_dir / "comm").read_text().strip()
            if comm not in desktop_procs:
                continue

            env = (proc_dir / "environ").read_bytes()
            for var in env.split(b"\x00"):
                if var.startswith(b"DBUS_SESSION_BUS_ADDRESS="):
                    return var.decode().split("=", 1)[1]
        except (PermissionError, FileNotFoundError, OSError):
            continue

    # Method 2: Check standard socket path
    socket_path = f"/run/user/{target_uid}/bus"
    if Path(socket_path).exists():
        return f"unix:path={socket_path}"

    # Method 3: Scan /tmp for dbus sockets
    for dbus_file in Path("/tmp").glob("dbus-*"):
        if dbus_file.is_socket():
            return f"unix:path={dbus_file}"

    return ""


def send_notification(title: str, message: str,
                      urgency: str = URGENCY_NORMAL,
                      alert_level: int = 0,
                      timeout_ms: int = 10000) -> bool:
    """Send a desktop notification to the logged-in user.

    Args:
        title: Notification title
        message: Notification body
        urgency: "low", "normal", or "critical"
        alert_level: XDR alert level (1-3), overrides urgency if set
        timeout_ms: Auto-dismiss timeout (0 = never dismiss)

    Returns True if notification was sent successfully.
    """
    if alert_level:
        urgency = ALERT_URGENCY.get(alert_level, URGENCY_NORMAL)

    icon = ALERT_ICONS.get(alert_level, "dialog-information")

    # Critical notifications should persist
    if urgency == URGENCY_CRITICAL:
        timeout_ms = 0  # Never auto-dismiss

    # Find D-Bus address
    user, uid = _find_display_user()
    dbus_addr = _find_dbus_address(user, uid)

    if not dbus_addr:
        logger.debug("No D-Bus session found — cannot send notification")
        return False

    # Build environment for notify-send
    env = os.environ.copy()
    env["DBUS_SESSION_BUS_ADDRESS"] = dbus_addr
    env["DISPLAY"] = os.environ.get("DISPLAY", ":0")

    try:
        cmd = [
            "notify-send",
            "-u", urgency,
            "-i", icon,
            "-t", str(timeout_ms),
            "-a", "XDR Security",
            title,
            message,
        ]

        # If running as root, use su to run as the target user
        if os.geteuid() == 0 and user:
            cmd = ["su", "-", user, "-c",
                   f'DBUS_SESSION_BUS_ADDRESS="{dbus_addr}" '
                   f'DISPLAY=":0" '
                   f'notify-send -u {urgency} -i {icon} '
                   f'-t {timeout_ms} -a "XDR Security" '
                   f'"{title}" "{message}"']
            env = None  # su handles its own env

        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=5, env=env
        )

        if result.returncode == 0:
            logger.debug(f"Notification sent: {title}")
            return True
        else:
            logger.debug(f"notify-send failed: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        logger.debug("notify-send timed out")
        return False
    except Exception as e:
        logger.debug(f"Notification error: {e}")
        return False


def send_xdr_alert(reason: str, detail: str, alert_level: int = 2):
    """Convenience function for XDR security alerts."""
    prefix = {1: "ℹ️", 2: "⚠️", 3: "🔴"}.get(alert_level, "")
    title = f"🛡️ XDR {prefix} {reason}"
    send_notification(title, detail, alert_level=alert_level)
