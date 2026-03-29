#!/usr/bin/env python3
"""
XDR EDR Detector — Advanced host-level threat detection (Facade).

This package splits the monolithic edr_detector into modular components:
- policy: Policy management (load/save/defaults)
- rules: Detection rule constants
- process_tracker: Process tree + event tracking + cleanup
- block_engine: Kill/block logic + failure logging
- detectors/: Individual detection modules
"""

import os
import time
import logging
from collections import defaultdict
from threading import Lock

from .policy import _load_policy, _save_policy, DEFAULT_POLICY
from .rules import MEMFD_PATTERNS, LOLBIN_RULES, SEQUENCE_PATTERNS
from .process_tracker import ProcessInfo, ProcessTracker
from .block_engine import BlockEngine

from .detectors.fileless import check_memfd
from .detectors.lolbins import check_lolbins, scan_cmdlines
from .detectors.ptrace import check_ptrace
from .detectors.beacon import check_beacon
from .detectors.container import check_container_escape
from .detectors.rootkit import check_kernel_integrity
from .detectors.sequence import check_sequences
from .detectors.lateral import check_lateral_movement
from .detectors.ssl_content import check_ssl_content


class EDRDetector:
    """Advanced EDR detection engine with auto-block policy."""

    # Paths that are always trusted (XDR's own files only)
    _TRUSTED_PATHS = ("/opt/xdr/",)
    # IDE paths — processes with these exe paths can inherit whitelist to children
    # (only checked in parent chain, NOT for direct trust)
    _TRUSTED_IDE_PATHS = ("/usr/share/antigravity/",)

    def __init__(self, blocklist_store):
        self.store = blocklist_store
        self._lock = Lock()
        # Process tracker (tree, events, cleanup)
        self.tracker = ProcessTracker()
        # Block engine (kill, hash, path)
        self.blocker = BlockEngine(blocklist_store)
        # Auto-block policy
        self.policy = _load_policy()
        # Ptrace tracking: {target_pid: {tracer_pid, tracer_comm, time}}
        self._ptrace_events = {}
        # Beacon/C2C tracking: {ip: [timestamps]}
        self._ip_connect_log = defaultdict(list)
        # Self PID (to skip own process tree)
        self._self_pid = os.getpid()
        # Parent whitelist cache: {pid: (scopes_set, expire_time)}
        self._wl_cache = {}

    # ── Policy management ──────────────────────────────────

    def reload_policy(self):
        """Hot-reload detector policy from disk."""
        self.policy = _load_policy()
        logging.info("EDR detector policy reloaded")

    def get_policy(self) -> dict:
        """Get current auto-block policy."""
        return dict(self.policy)

    def update_policy(self, updates: dict) -> dict:
        """Update policy settings. Returns new policy."""
        for key, val in updates.items():
            self.policy[key] = val
        _save_policy(self.policy)
        return dict(self.policy)

    def _should_auto_block(self, detector: str) -> bool:
        """Check if a detector should auto-block (kill) or just alert."""
        per_detector = self.policy.get(f"auto_block_{detector}")
        if per_detector is not None:
            return per_detector
        return self.policy.get("auto_block", False)

    def _get_whitelist_scopes(self, comm: str, path: str) -> set:
        """Return set of scopes this comm/path is whitelisted for."""
        from fnmatch import fnmatch
        scopes = set()
        rules = self.policy.get("whitelist_rules", [])
        for rule in rules:
            matched = False
            rule_comm = rule.get("comm", "")
            rule_path = rule.get("path", "")
            if rule_comm and comm and fnmatch(comm, rule_comm):
                matched = True
            if rule_path and path and fnmatch(path, rule_path):
                matched = True
            if matched:
                scopes.add(rule.get("scope", "all"))
        return scopes

    def _check_parent_whitelist(self, pid: int, ppid: int) -> set:
        """Check if any ancestor process is whitelisted (inherit to children).
        Cache key = (ppid, start_time) to prevent PID reuse bypass."""
        now = time.time()

        # Get process start time for safe caching (prevents PID recycling attack)
        ppid_starttime = self._get_proc_starttime(ppid)
        cache_key = (ppid, ppid_starttime)

        # Check cache — only valid if start_time matches (same process)
        cached = self._wl_cache.get(cache_key)
        if cached and cached[1] > now:
            return cached[0]

        scopes = set()
        visited = set()
        current = ppid

        # Walk up to 10 levels of parent chain
        for _ in range(10):
            if current <= 1 or current in visited:
                break
            visited.add(current)

            try:
                with open(f"/proc/{current}/comm") as f:
                    parent_comm = f.read().strip()
                parent_path = ""
                try:
                    parent_path = os.readlink(f"/proc/{current}/exe")
                except OSError:
                    pass

                parent_scopes = self._get_whitelist_scopes(parent_comm, parent_path)
                # Also trust children of IDE processes (parent's exe in _TRUSTED_IDE_PATHS)
                if parent_path and any(parent_path.startswith(tp)
                                       for tp in self._TRUSTED_IDE_PATHS):
                    parent_scopes.add("all")
                if "all" in parent_scopes:
                    result = {"all"}
                    self._wl_cache[cache_key] = (result, now + 60)
                    return result
                scopes |= parent_scopes

                with open(f"/proc/{current}/status") as f:
                    for line in f:
                        if line.startswith("PPid:"):
                            current = int(line.split(":")[1].strip())
                            break
                    else:
                        break
            except (OSError, PermissionError, ValueError):
                break

        self._wl_cache[cache_key] = (scopes, now + 60)
        # Cleanup stale cache entries periodically
        if len(self._wl_cache) > 500:
            self._wl_cache = {k: v for k, v in self._wl_cache.items() if v[1] > now}

        return scopes

    @staticmethod
    def _get_proc_starttime(pid: int) -> int:
        """Get process start time from /proc/[pid]/stat (field 22).
        This is monotonic and unique per process lifecycle,
        so (pid, starttime) is a globally unique process identifier."""
        try:
            with open(f"/proc/{pid}/stat") as f:
                fields = f.read().rsplit(")", 1)[-1].split()
                # Field 22 is starttime, but after ')' split it's index 19
                return int(fields[19])
        except (OSError, IndexError, ValueError):
            return 0

    # ── Main detection pipeline ──────────────────────────

    def check_exec(self, event: dict) -> dict | None:
        """
        Check a process exec event. Returns action dict if threat detected.
        Pipeline: whitelist → blocklist → memfd → LOLBins → sequence.
        """
        pid = event.get("pid", 0)
        ppid = event.get("ppid", 0)
        comm = event.get("comm", "")
        path = event.get("filename", "")
        uid = event.get("uid", 0)
        cmdline = event.get("cmdline", "")

        # Track in process tree
        proc = ProcessInfo(pid, ppid, comm, path, uid)
        self.tracker.track_process(proc)

        # ── Skip XDR's own processes ──
        if path and any(path.startswith(tp) for tp in self._TRUSTED_PATHS):
            return None
        if ppid == self._self_pid:
            return None  # Direct child of XDR engine

        # ── Whitelist check (including parent chain) ──
        self._whitelisted_scopes = self._get_whitelist_scopes(comm, path)
        # Also check parent chain — if parent is whitelisted, child inherits
        if "all" not in self._whitelisted_scopes:
            self._whitelisted_scopes |= self._check_parent_whitelist(pid, ppid)
        if "all" in self._whitelisted_scopes:
            return None  # Fully whitelisted, skip all detection

        # 1. Path-based check (always kill — explicit blocklist)
        if path and self.blocker.check_path_blocked(path):
            self.blocker.kill_pid(pid)
            return {
                "action": "KILL",
                "reason": "BLOCKED_PATH",
                "detail": f"경로 차단됨: {path}",
                "alert_level": 3,
                "pid": pid,
                "path": path,
            }

        # 2. SHA256 hash check (always kill — explicit blocklist)
        if path:
            sha = self.blocker.get_sha256(path)
            if sha:
                proc.sha256 = sha
                if self.blocker.check_hash_blocked(sha):
                    self.blocker.kill_pid(pid)
                    return {
                        "action": "KILL",
                        "reason": "BLOCKED_HASH",
                        "detail": f"해시 차단됨: {sha[:16]}... ({path})",
                        "alert_level": 3,
                        "pid": pid,
                        "path": path,
                        "sha256": sha,
                    }

        # 3. Fileless malware detection (memfd/proc)
        memfd_alert = check_memfd(pid, path, comm,
                                  self._should_auto_block("memfd"),
                                  self.blocker)
        if memfd_alert:
            return memfd_alert

        # 4. LOLBins detection (suspicious argv)
        lolbin_alert = check_lolbins(pid, comm, cmdline, path,
                                     self.policy,
                                     self._should_auto_block("lolbins"),
                                     self.blocker)
        if lolbin_alert:
            return lolbin_alert

        # 5. Track event for sequence analysis
        self.tracker.track_event(pid, event)

        # 6. Check behavioral sequences
        seq_alert = check_sequences(pid, self.tracker.get_pid_events())
        if seq_alert:
            return seq_alert

        # Periodic cleanup
        if time.time() - self.tracker.last_cleanup > 120:
            self.tracker.cleanup(self._ptrace_events, self._ip_connect_log)
            self.tracker.last_cleanup = time.time()

        return None

    def check_event(self, event: dict) -> dict | None:
        """Check non-exec events for sequence patterns + C2C beaconing."""
        pid = event.get("pid", 0)
        event_type = event.get("event_type", 0)
        self.tracker.track_event(pid, event)

        # Ptrace monitoring (event_type would be custom)
        if event_type == 6:  # PTRACE event
            ptrace_alert = check_ptrace(
                event, self.policy, self.tracker,
                self._should_auto_block("ptrace"),
                self.blocker, self._ptrace_events)
            if ptrace_alert:
                return ptrace_alert

        # C2C beacon detection (repeated connects to same IP)
        if event_type == 3:  # NET_CONNECT
            dst_ip = event.get("dst_ip", "")
            if dst_ip and dst_ip not in ("0.0.0.0", "127.0.0.1", "::"):
                beacon_alert = check_beacon(pid, dst_ip, event,
                                            self._ip_connect_log)
                if beacon_alert:
                    return beacon_alert

        return check_sequences(pid, self.tracker.get_pid_events())

    def check_container_escape(self, event: dict) -> dict | None:
        """Detect container/VM escape attempts."""
        return check_container_escape(
            event, self._should_auto_block("container_escape"),
            self.blocker)

    def check_kernel_integrity(self) -> list[dict]:
        """Periodic kernel integrity checks."""
        return check_kernel_integrity(
            self.policy, self._should_auto_block("rootkit"),
            self.tracker)

    def check_lateral_movement(self, event: dict) -> dict | None:
        """Detect lateral movement."""
        return check_lateral_movement(
            event, self.policy, self._ip_connect_log,
            self._should_auto_block("lateral"), self.blocker)

    def check_ssl_content(self, event: dict) -> dict | None:
        """Analyze SSL/TLS plaintext captured by eBPF uprobe."""
        return check_ssl_content(event)

    def scan_cmdlines(self) -> list[dict]:
        """Scan all running process cmdlines for LOLBin patterns."""
        return scan_cmdlines(self.policy)

    # ── Delegated methods ────────────────────────────────

    def kill_and_block(self, pid: int) -> dict:
        """Kill PID immediately + permanently block its path and hash."""
        return self.blocker.kill_and_block(pid)

    def get_process_tree(self) -> list:
        """Return current process tree as list of dicts."""
        return self.tracker.get_process_tree()

    def get_process_chain(self, pid: int) -> list:
        """Get parent chain for a PID."""
        return self.tracker.get_process_chain(pid)
