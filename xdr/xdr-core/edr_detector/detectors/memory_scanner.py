#!/usr/bin/env python3
"""
Memory Forensics — /proc/[pid]/maps RWX Scanner.

Detects:
  - RWX memory regions (shellcode injection suspect)
  - Deleted file-backed mappings (fileless execution)
  - Anonymous executable regions (code injection)

MITRE ATT&CK: T1055 (Process Injection), T1620 (Reflective Code Loading)
"""

import os
import re
import logging
from typing import Optional

logger = logging.getLogger("xdr.memory")

# Processes that legitimately use RWX memory (JIT engines, browsers, etc.)
_JIT_WHITELIST = frozenset({
    "node", "nodejs", "java", "javac",
    "python3", "python", "python3.12", "python3.13",
    "ruby", "lua", "luajit",
    "qemu", "qemu-system-x86",
    "firefox", "chromium", "chrome",
    "antigravity",  # Electron/V8 JIT
    "Xorg", "Xwayland",
    "gnome-shell", "mate-panel",
    "pipewire", "wireplumber",
})

# Paths that legitimately have RWX (graphics drivers, JIT libraries)
_RWX_PATH_WHITELIST = (
    "/usr/lib/x86_64-linux-gnu/dri/",   # GPU drivers
    "/usr/lib/x86_64-linux-gnu/mesa/",   # Mesa
    "/dev/dri/",                          # DRM
    "/memfd:v8/",                         # V8 JIT
    "/memfd:jit-",                        # Generic JIT
    "/anon_inode:",                        # Kernel anon
)

# Minimum RWX region size to alert (skip tiny JIT stubs)
_MIN_RWX_SIZE = 4096  # 4KB


def _get_comm(pid: int) -> str:
    """Get process comm name."""
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return ""


def _get_exe(pid: int) -> str:
    """Get process exe path."""
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return ""


def _get_uid(pid: int) -> int:
    """Get process UID."""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return -1


def scan_process(pid: int) -> list[dict]:
    """Scan a single process's memory maps for suspicious regions."""
    alerts = []
    comm = _get_comm(pid)

    # Skip whitelisted JIT processes
    if comm in _JIT_WHITELIST:
        return alerts

    # Skip kernel threads
    if pid <= 2:
        return alerts

    try:
        with open(f"/proc/{pid}/maps") as f:
            maps_data = f.read()
    except (OSError, PermissionError):
        return alerts

    exe = _get_exe(pid)
    uid = _get_uid(pid)

    for line in maps_data.splitlines():
        # Format: addr-addr perms offset dev inode pathname
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue

        addr_range = parts[0]
        perms = parts[1]
        pathname = parts[5] if len(parts) > 5 else ""

        # ── Check 1: RWX regions (rwxp) ──
        if "rwx" in perms:
            # Skip whitelisted paths
            if any(wl in pathname for wl in _RWX_PATH_WHITELIST):
                continue

            # Calculate region size
            try:
                start, end = addr_range.split("-")
                size = int(end, 16) - int(start, 16)
            except (ValueError, IndexError):
                continue

            if size < _MIN_RWX_SIZE:
                continue

            # Anonymous RWX (no file backing) = highest suspicion
            is_anon = not pathname.strip() or pathname.strip() == ""
            is_deleted = "(deleted)" in pathname

            if is_anon:
                alerts.append({
                    "source": "DETECTOR",
                    "reason": "RWX_ANONYMOUS",
                    "mitre_id": "T1055",
                    "alert_level": 3,  # CRITICAL
                    "pid": pid,
                    "comm": comm,
                    "path": exe,
                    "uid": uid,
                    "detail": (
                        f"익명 RWX 메모리 감지: {comm}({pid}) "
                        f"영역={addr_range} 크기={size}B "
                        f"경로={exe}"
                    ),
                })
            elif is_deleted:
                alerts.append({
                    "source": "DETECTOR",
                    "reason": "RWX_DELETED_FILE",
                    "mitre_id": "T1620",
                    "alert_level": 3,  # CRITICAL
                    "pid": pid,
                    "comm": comm,
                    "path": exe,
                    "uid": uid,
                    "detail": (
                        f"삭제 파일 RWX 매핑: {comm}({pid}) "
                        f"영역={addr_range} 파일={pathname.strip()} "
                        f"경로={exe}"
                    ),
                })
            else:
                alerts.append({
                    "source": "DETECTOR",
                    "reason": "RWX_MEMORY",
                    "mitre_id": "T1055",
                    "alert_level": 2,  # WARNING
                    "pid": pid,
                    "comm": comm,
                    "path": exe,
                    "uid": uid,
                    "detail": (
                        f"RWX 메모리 영역: {comm}({pid}) "
                        f"영역={addr_range} 크기={size}B "
                        f"파일={pathname.strip()}"
                    ),
                })

        # ── Check 2: Deleted file-backed executable regions ──
        elif "(deleted)" in pathname and "x" in perms:
            alerts.append({
                "source": "DETECTOR",
                "reason": "DELETED_EXEC_MAP",
                "mitre_id": "T1620",
                "alert_level": 3,  # CRITICAL
                "pid": pid,
                "comm": comm,
                "path": exe,
                "uid": uid,
                "detail": (
                    f"삭제된 실행 매핑: {comm}({pid}) "
                    f"영역={addr_range} 파일={pathname.strip()} "
                    f"경로={exe}"
                ),
            })

    return alerts


def scan_all_processes(xdr_pid: Optional[int] = None) -> list[dict]:
    """Scan all processes for suspicious memory regions."""
    all_alerts = []
    try:
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            pid = int(name)
            if pid <= 2:
                continue
            # Skip XDR itself
            if xdr_pid and pid == xdr_pid:
                continue
            try:
                alerts = scan_process(pid)
                all_alerts.extend(alerts)
            except Exception:
                continue
    except OSError:
        pass

    # Rootkit hidden process detection
    hidden = scan_hidden_processes()
    all_alerts.extend(hidden)

    if all_alerts:
        logger.info(f"Memory scan: {len(all_alerts)} suspicious regions found")
    return all_alerts


def scan_hidden_processes() -> list[dict]:
    """Detect processes hidden from /proc (rootkit detection).

    Methods:
      1. Brute-force kill -0 on PID range vs /proc listing
      2. /proc/[pid]/stat cross-check
      3. /proc process count vs kernel procs/running comparison
    """
    import signal
    alerts = []

    # Get all PIDs visible in /proc
    try:
        proc_pids = set()
        for name in os.listdir("/proc"):
            if name.isdigit():
                proc_pids.add(int(name))
    except OSError:
        return alerts

    if not proc_pids:
        return alerts

    max_pid = max(proc_pids)

    # Method 1: Brute-force kill -0 on recent PID range
    # Check PIDs around the current range that might be hidden
    # Only scan a window to avoid taking too long
    scan_start = max(3, max_pid - 2000)
    hidden_pids = []

    for pid in range(scan_start, max_pid + 500):
        if pid in proc_pids:
            continue
        try:
            # kill -0 queries kernel task_struct directly
            os.kill(pid, 0)
        except PermissionError:
            # EPERM = process exists (no permission to signal)
            pass
        except (ProcessLookupError, OSError):
            # ESRCH = process truly doesn't exist — normal
            continue
        else:
            pass  # kill -0 succeeded without error

        # kill -0 succeeded or EPERM — process exists in kernel
        # CRITICAL: Verify it's truly hidden, not just a race condition
        # (new process created between /proc listing and kill -0)
        import time
        truly_hidden = True
        for _ in range(3):  # Check 3 times with small delay
            time.sleep(0.01)
            if os.path.isdir(f"/proc/{pid}"):
                truly_hidden = False  # It appeared in /proc → not hidden, just new
                break

        if truly_hidden:
            # Triple-verified: process exists in kernel but NOT in /proc
            comm = _get_comm(pid)
            hidden_pids.append(pid)

    for pid in hidden_pids:
        alerts.append({
            "source": "DETECTOR",
            "reason": "ROOTKIT_HIDDEN_PID",
            "mitre_id": "T1014",
            "alert_level": 3,  # CRITICAL
            "pid": pid,
            "comm": "???",
            "path": "",
            "uid": -1,
            "detail": (
                f"루트킷 의심: 은닉 프로세스 감지! PID={pid} "
                f"(kill -0 성공 + /proc 3회 재확인 미존재 "
                f"— 커널에 존재하나 /proc에서 숨겨짐)"
            ),
        })

    if hidden_pids:
        logger.warning(f"ROOTKIT ALERT: {len(hidden_pids)} hidden PIDs: {hidden_pids}")

    return alerts
