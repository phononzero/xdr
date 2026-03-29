"""
EDR Detector — Process Lineage (Real-time Process Tree Tracking).

Maintains a live process tree from eBPF exec/exit events.
Detects suspicious process chains (attack kill chains).
"""

import time
import logging
from collections import defaultdict
from threading import Lock

logger = logging.getLogger("xdr.lineage")

# ── Attack chain patterns ─────────────────────────────
# Each pattern: list of (comm_regex, description) tuples
# If a process chain matches sequential steps → alert
ATTACK_CHAINS = [
    {
        "name": "리버스 쉘 체인",
        "mitre": "T1059.004",
        "steps": ["sshd", "bash", "curl|wget|nc|ncat"],
        "severity": 3,
    },
    {
        "name": "자격증명 탈취",
        "mitre": "T1003",
        "steps": ["bash", "cat|less|head|tail|grep"],
        "target_files": ["shadow", "passwd", "gshadow"],
        "severity": 3,
    },
    {
        "name": "정찰 → 유출 체인",
        "mitre": "T1018+T1041",
        "steps": ["bash", "whoami|id|hostname|uname", "curl|wget|nc"],
        "severity": 3,
    },
    {
        "name": "지속성 확보",
        "mitre": "T1053.003",
        "steps": ["bash", "crontab|systemctl|at"],
        "severity": 2,
    },
    {
        "name": "방어 회피",
        "mitre": "T1070.004",
        "steps": ["bash", "rm|shred|unlink"],
        "target_files": [".bash_history", "auth.log", "syslog", "wtmp"],
        "severity": 3,
    },
    {
        "name": "인코딩 기반 유출",
        "mitre": "T1132",
        "steps": ["bash", "base64|xxd|openssl"],
        "severity": 2,
    },
    {
        "name": "권한 상승 시도",
        "mitre": "T1548.003",
        "steps": ["bash", "sudo|su|pkexec|doas"],
        "severity": 2,
    },
]


class ProcessNode:
    """Single process in the lineage tree."""
    __slots__ = ("pid", "ppid", "comm", "exe", "cmdline", "uid",
                 "start_time", "children", "alive")

    def __init__(self, pid, ppid, comm, exe, cmdline, uid, start_time):
        self.pid = pid
        self.ppid = ppid
        self.comm = comm
        self.exe = exe
        self.cmdline = cmdline
        self.uid = uid
        self.start_time = start_time
        self.children = set()  # child PIDs
        self.alive = True


class ProcessLineage:
    """Real-time process tree with attack chain detection."""

    MAX_NODES = 50000       # Max tracked processes
    CLEANUP_INTERVAL = 300  # Cleanup dead nodes every 5 min
    DEAD_RETENTION = 60     # Keep dead process info for 60s

    def __init__(self):
        self._tree = {}  # pid -> ProcessNode
        self._lock = Lock()
        self._last_cleanup = time.time()

    def on_exec(self, pid, ppid, comm, exe, cmdline, uid):
        """Called on EVT_PROCESS_EXEC."""
        now = time.time()
        node = ProcessNode(pid, ppid, comm, exe, cmdline, uid, now)

        with self._lock:
            self._tree[pid] = node
            # Link to parent
            parent = self._tree.get(ppid)
            if parent:
                parent.children.add(pid)

            # Periodic cleanup
            if now - self._last_cleanup > self.CLEANUP_INTERVAL:
                self._cleanup(now)

        # Check for attack chains
        return self._check_attack_chains(pid)

    def on_exit(self, pid):
        """Called on EVT_PROCESS_EXIT."""
        with self._lock:
            node = self._tree.get(pid)
            if node:
                node.alive = False

    def get_chain(self, pid, max_depth=10):
        """Get the ancestor chain for a PID."""
        chain = []
        visited = set()
        current = pid
        with self._lock:
            for _ in range(max_depth):
                if current in visited or current <= 1:
                    break
                visited.add(current)
                node = self._tree.get(current)
                if not node:
                    break
                chain.append({
                    "pid": node.pid,
                    "comm": node.comm,
                    "cmdline": node.cmdline,
                    "uid": node.uid,
                })
                current = node.ppid
        return chain

    def get_children(self, pid, max_depth=5):
        """Get all descendants of a PID."""
        result = []
        with self._lock:
            self._collect_children(pid, result, max_depth, 0)
        return result

    def _collect_children(self, pid, result, max_depth, depth):
        if depth >= max_depth:
            return
        node = self._tree.get(pid)
        if not node:
            return
        for cpid in node.children:
            child = self._tree.get(cpid)
            if child:
                result.append({
                    "pid": child.pid,
                    "comm": child.comm,
                    "cmdline": child.cmdline,
                    "depth": depth + 1,
                })
                self._collect_children(cpid, result, max_depth, depth + 1)

    def _check_attack_chains(self, pid):
        """Check if the process chain matches any attack patterns."""
        import re
        chain = self.get_chain(pid, max_depth=8)
        if len(chain) < 2:
            return None

        # chain[0] = current process, chain[1] = parent, ...
        chain_comms = [c["comm"] for c in chain]
        chain_cmdlines = [c.get("cmdline", "") for c in chain]

        for pattern in ATTACK_CHAINS:
            steps = pattern["steps"]
            if len(chain_comms) < len(steps):
                continue

            # Check if chain matches pattern (reversed, since chain[0]=current)
            matched = True
            for i, step_regex in enumerate(reversed(steps)):
                idx = len(chain_comms) - 1 - i
                if idx < 0:
                    matched = False
                    break
                if not re.match(f"^({step_regex})$", chain_comms[idx]):
                    matched = False
                    break

            if matched:
                # Check target_files if specified
                if "target_files" in pattern:
                    cmdline_str = " ".join(chain_cmdlines)
                    file_match = any(
                        tf in cmdline_str for tf in pattern["target_files"]
                    )
                    if not file_match:
                        continue

                chain_desc = " → ".join(
                    f"{c['comm']}({c['pid']})" for c in reversed(chain)
                )
                return {
                    "alert_level": pattern["severity"],
                    "reason": "ATTACK_CHAIN",
                    "mitre_id": pattern.get("mitre", ""),
                    "detail": (
                        f"공격 체인 감지: {pattern['name']} "
                        f"[{pattern.get('mitre', '')}] | "
                        f"체인: {chain_desc}"
                    ),
                    "chain": chain,
                }

        return None

    def _cleanup(self, now):
        """Remove dead processes older than retention period."""
        to_remove = []
        for pid, node in self._tree.items():
            if not node.alive and (now - node.start_time) > self.DEAD_RETENTION:
                to_remove.append(pid)

        for pid in to_remove:
            node = self._tree.pop(pid, None)
            if node:
                parent = self._tree.get(node.ppid)
                if parent:
                    parent.children.discard(pid)

        # Hard cap
        if len(self._tree) > self.MAX_NODES:
            excess = len(self._tree) - self.MAX_NODES
            oldest = sorted(self._tree.values(), key=lambda n: n.start_time)[:excess]
            for node in oldest:
                self._tree.pop(node.pid, None)

        self._last_cleanup = now
        logger.debug(f"Lineage cleanup: {len(to_remove)} removed, {len(self._tree)} active")
