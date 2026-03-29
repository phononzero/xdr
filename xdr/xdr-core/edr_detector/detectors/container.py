#!/usr/bin/env python3
"""Container/VM escape detection."""

import os


def check_container_escape(event: dict, auto_block: bool,
                           blocker) -> dict | None:
    """
    Detect container/VM escape attempts:
    - Namespace change (setns syscall from container)
    - Cgroup escape (write to cgroup release_agent)
    - Host mount access from container namespace
    - Docker socket access from container
    """
    pid = event.get("pid", 0)
    comm = event.get("comm", "")
    path = event.get("filename", "")
    syscall = event.get("syscall", "")

    # Detect namespace change (setns/unshare from container)
    if syscall in ("setns", "unshare"):
        ns_type = event.get("ns_type", "")
        if _is_containerized(pid):
            action = "ALERT"
            if auto_block:
                blocker.kill_pid(pid)
                action = "KILL"
            return {
                "action": action,
                "reason": "CONTAINER_ESCAPE",
                "detail": f"네임스페이스 변경 시도: {comm}(pid={pid}) "
                         f"syscall={syscall} ns={ns_type}",
                "alert_level": 3,
                "pid": pid,
                "auto_blocked": action == "KILL",
            }

    # Detect cgroup escape
    if path and ("release_agent" in path or
                 "notify_on_release" in path or
                 "/sys/fs/cgroup" in path):
        if _is_containerized(pid):
            action = "ALERT"
            if auto_block:
                blocker.kill_pid(pid)
                action = "KILL"
            return {
                "action": action,
                "reason": "CGROUP_ESCAPE",
                "detail": f"cgroup 탈출 시도: {comm}(pid={pid}) → {path}",
                "alert_level": 3,
                "pid": pid,
                "auto_blocked": action == "KILL",
            }

    # Detect Docker socket access from container
    if path and path in ("/var/run/docker.sock",
                         "/run/docker.sock",
                         "/var/run/containerd/containerd.sock"):
        if _is_containerized(pid):
            return {
                "action": "ALERT",
                "reason": "CONTAINER_SOCKET_ACCESS",
                "detail": f"컨테이너에서 호스트 소켓 접근: "
                         f"{comm}(pid={pid}) → {path}",
                "alert_level": 3,
                "pid": pid,
            }

    # Detect /proc/1/root access (host filesystem from container)
    if path and ("/proc/1/root" in path or
                 "/proc/sysrq-trigger" in path):
        if _is_containerized(pid):
            action = "ALERT"
            if auto_block:
                blocker.kill_pid(pid)
                action = "KILL"
            return {
                "action": action,
                "reason": "HOST_FS_ACCESS",
                "detail": f"호스트 파일시스템 접근: {comm}(pid={pid}) → {path}",
                "alert_level": 3,
                "pid": pid,
                "auto_blocked": action == "KILL",
            }

    return None


def _is_containerized(pid: int) -> bool:
    """Check if PID runs inside a container by comparing namespaces."""
    try:
        pid_ns = os.readlink(f"/proc/{pid}/ns/pid")
        init_ns = os.readlink("/proc/1/ns/pid")
        return pid_ns != init_ns
    except (OSError, PermissionError):
        return False
