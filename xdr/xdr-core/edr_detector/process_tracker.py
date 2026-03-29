#!/usr/bin/env python3
"""
EDR Detector — Process tree tracking, event history, and cleanup.
"""

import time
from collections import defaultdict
from threading import Lock


class ProcessInfo:
    """Info about a tracked process."""
    __slots__ = ['pid', 'ppid', 'comm', 'path', 'uid', 'start_time', 'sha256']

    def __init__(self, pid, ppid=0, comm="", path="", uid=0):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm
        self.path = path
        self.uid = uid
        self.start_time = time.time()
        self.sha256 = None


class ProcessTracker:
    """Track process tree, event history, and cleanup."""

    def __init__(self):
        self._lock = Lock()
        self._processes = {}  # pid -> ProcessInfo
        self._pid_events = defaultdict(list)  # PID -> [events]
        self.last_cleanup = time.time()

    def track_process(self, proc: ProcessInfo):
        """Add/update a process in the tree."""
        with self._lock:
            self._processes[proc.pid] = proc

    def track_event(self, pid: int, event: dict):
        """Track event for sequence analysis."""
        self._pid_events[pid].append({
            "time": time.time(),
            "type": event.get("event_type", 0),
            "path": event.get("filename", ""),
            "dst_ip": event.get("dst_ip", 0),
            **event,
        })
        # Keep only recent events
        if len(self._pid_events[pid]) > 50:
            self._pid_events[pid] = self._pid_events[pid][-50:]

    def get_pid_events(self) -> dict:
        """Return reference to pid_events dict."""
        return self._pid_events

    def get_process_tree(self) -> list:
        """Return current process tree as list of dicts."""
        with self._lock:
            return [
                {
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "comm": p.comm,
                    "path": p.path,
                    "uid": p.uid,
                    "start_time": p.start_time,
                    "sha256": p.sha256,
                }
                for p in self._processes.values()
            ]

    def get_process_chain(self, pid: int) -> list:
        """Get parent chain for a PID."""
        chain = []
        visited = set()
        with self._lock:
            current_pid = pid
            while current_pid and current_pid not in visited:
                visited.add(current_pid)
                proc = self._processes.get(current_pid)
                if not proc:
                    break
                chain.append({
                    "pid": proc.pid, "ppid": proc.ppid,
                    "comm": proc.comm, "path": proc.path,
                })
                current_pid = proc.ppid
        return chain

    def get_process(self, pid: int):
        """Get ProcessInfo by pid."""
        with self._lock:
            return self._processes.get(pid)

    def cleanup(self, ptrace_events: dict = None, ip_connect_log: dict = None):
        """Clean up old process entries and event histories."""
        cutoff = time.time() - 300  # 5 minutes
        with self._lock:
            old_pids = [
                pid for pid, p in self._processes.items()
                if p.start_time < cutoff
            ]
            for pid in old_pids:
                del self._processes[pid]

        old_evt_pids = [
            pid for pid, evts in self._pid_events.items()
            if not evts or evts[-1]["time"] < cutoff
        ]
        for pid in old_evt_pids:
            del self._pid_events[pid]

        # Cleanup beacon tracking
        if ip_connect_log is not None:
            beacon_cutoff = time.time() - 600
            dead_ips = [ip for ip, ts in ip_connect_log.items()
                        if not ts or (isinstance(ts, list) and
                                      (not ts or (isinstance(ts[-1], (int, float)) and ts[-1] < beacon_cutoff)))]
            for ip in dead_ips:
                del ip_connect_log[ip]

        # Cleanup ptrace tracking
        if ptrace_events is not None:
            ptrace_cutoff = time.time() - 120
            dead_ptrace = [pid for pid, info in ptrace_events.items()
                           if info["time"] < ptrace_cutoff]
            for pid in dead_ptrace:
                del ptrace_events[pid]
