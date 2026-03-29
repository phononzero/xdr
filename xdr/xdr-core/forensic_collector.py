#!/usr/bin/env python3
"""
XDR Forensic Collector — Automated evidence collection on CRITICAL alerts.

When a CRITICAL alert fires, this module automatically collects:
  - Process info (maps, status, cmdline, environ, fd list)
  - File hashes (SHA256)
  - Network state (/proc/[pid]/net/tcp)
  - Parent chain snapshot
  - Timeline entry

Evidence is stored in /opt/xdr/forensics/ with chain-of-custody metadata.

MITRE ATT&CK: T1005 (Data from Local System)
"""

import os
import json
import hashlib
import logging
import time
from datetime import datetime
from pathlib import Path
from threading import Lock

logger = logging.getLogger("xdr.forensics")

try:
    from errors import ForensicCollectionError, ForensicStorageError
except ImportError:
    ForensicCollectionError = ForensicStorageError = Exception

FORENSICS_DIR = Path("/opt/xdr/forensics")
MAX_FORENSIC_FILES = 500  # Keep last 500 evidence packages


class ForensicCollector:
    """Automated forensic evidence collector."""

    def __init__(self):
        self._lock = Lock()
        self._collection_count = 0
        FORENSICS_DIR.mkdir(parents=True, exist_ok=True)

    def collect(self, alert: dict) -> str | None:
        """Collect forensic evidence for a CRITICAL alert.

        Returns path to evidence file, or None on failure.
        """
        pid = alert.get("pid", 0)
        reason = alert.get("reason", "UNKNOWN")
        if not pid or pid <= 2:
            return None

        try:
            ts = datetime.now()
            filename = (
                f"{ts.strftime('%Y%m%d_%H%M%S')}"
                f"_pid{pid}_{reason}.json"
            )
            filepath = FORENSICS_DIR / filename

            evidence = {
                "metadata": {
                    "collected_at": ts.isoformat(),
                    "collector": "XDR ForensicCollector",
                    "trigger_alert": {
                        "reason": reason,
                        "mitre_id": alert.get("mitre_id", ""),
                        "alert_level": alert.get("alert_level", 0),
                        "detail": alert.get("detail", ""),
                    },
                    "target_pid": pid,
                    "host": os.uname().nodename,
                },
                "process": self._collect_process_info(pid),
                "memory_maps": self._collect_maps(pid),
                "file_descriptors": self._collect_fds(pid),
                "network_state": self._collect_network(pid),
                "parent_chain": self._collect_parent_chain(pid),
                "related_files": self._collect_file_hashes(alert),
                "environment": self._collect_environ(pid),
            }

            # Calculate evidence hash for integrity
            evidence_json = json.dumps(evidence, indent=2, default=str)
            evidence["metadata"]["evidence_sha256"] = hashlib.sha256(
                evidence_json.encode()
            ).hexdigest()

            with open(filepath, "w") as f:
                json.dump(evidence, f, indent=2, default=str)

            with self._lock:
                self._collection_count += 1

            logger.info(f"Forensic evidence collected: {filepath}")
            self._cleanup_old()
            return str(filepath)

        except PermissionError as e:
            err = ForensicStorageError(str(filepath), str(e)) if 'filepath' in dir() else ForensicCollectionError(pid, str(e))
            err.log() if hasattr(err, 'log') else logger.warning(f"[FORENSIC_ERROR] {e}")
            return None
        except Exception as e:
            logger.error(f"[FORENSIC_COLLECTION_FAILED] pid={pid}: {e}")
            return None

    # ── Evidence collection methods ──────────────────────

    def _collect_process_info(self, pid: int) -> dict:
        """Collect process status, cmdline, cwd, exe."""
        info = {"pid": pid, "exists": False}
        proc = Path(f"/proc/{pid}")
        if not proc.exists():
            return info

        info["exists"] = True

        # /proc/[pid]/status
        try:
            with open(proc / "status") as f:
                for line in f:
                    key, _, val = line.partition(":")
                    key = key.strip()
                    val = val.strip()
                    if key in ("Name", "State", "PPid", "Uid", "Gid",
                               "Threads", "VmRSS", "VmSize", "VmPeak"):
                        info[key.lower()] = val
        except OSError:
            pass

        # /proc/[pid]/cmdline
        try:
            with open(proc / "cmdline", "rb") as f:
                info["cmdline"] = f.read().replace(b"\x00", b" ").decode(
                    "utf-8", errors="replace").strip()
        except OSError:
            pass

        # /proc/[pid]/exe
        try:
            info["exe"] = os.readlink(proc / "exe")
        except OSError:
            info["exe"] = ""

        # /proc/[pid]/cwd
        try:
            info["cwd"] = os.readlink(proc / "cwd")
        except OSError:
            info["cwd"] = ""

        # Start time
        try:
            with open(proc / "stat") as f:
                stat = f.read().split(")")[-1].split()
                # Field 20 (0-indexed from after ')') = starttime
                if len(stat) > 19:
                    info["start_time_ticks"] = int(stat[19])
        except (OSError, ValueError, IndexError):
            pass

        return info

    def _collect_maps(self, pid: int) -> list[dict]:
        """Collect memory maps, focusing on suspicious regions."""
        maps = []
        try:
            with open(f"/proc/{pid}/maps") as f:
                for line in f:
                    parts = line.split(None, 5)
                    if len(parts) < 5:
                        continue
                    perms = parts[1]
                    # Collect all executable or writable+executable regions
                    if "x" in perms or "w" in perms:
                        maps.append({
                            "address": parts[0],
                            "perms": perms,
                            "offset": parts[2],
                            "dev": parts[3],
                            "inode": parts[4],
                            "pathname": parts[5].strip() if len(parts) > 5 else "",
                        })
        except (OSError, PermissionError):
            pass
        return maps[:200]  # Limit size

    def _collect_fds(self, pid: int) -> list[dict]:
        """Collect file descriptor info."""
        fds = []
        fd_dir = Path(f"/proc/{pid}/fd")
        try:
            for fd_path in sorted(fd_dir.iterdir(), key=lambda p: int(p.name) if p.name.isdigit() else 0):
                try:
                    target = os.readlink(fd_path)
                    fds.append({
                        "fd": fd_path.name,
                        "target": target,
                    })
                except OSError:
                    continue
        except (OSError, PermissionError):
            pass
        return fds[:100]

    def _collect_network(self, pid: int) -> dict:
        """Collect network connection state."""
        net = {"tcp": [], "tcp6": []}
        for proto in ("tcp", "tcp6"):
            try:
                with open(f"/proc/{pid}/net/{proto}") as f:
                    header = True
                    for line in f:
                        if header:
                            header = False
                            continue
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            net[proto].append({
                                "local": parts[1],
                                "remote": parts[2],
                                "state": parts[3],
                            })
            except (OSError, PermissionError):
                pass
        return net

    def _collect_parent_chain(self, pid: int, depth: int = 10) -> list[dict]:
        """Walk parent chain up to init."""
        chain = []
        current = pid
        for _ in range(depth):
            if current <= 1:
                break
            info = {}
            try:
                with open(f"/proc/{current}/status") as f:
                    for line in f:
                        if line.startswith("Name:"):
                            info["comm"] = line.split(":")[1].strip()
                        elif line.startswith("PPid:"):
                            info["ppid"] = int(line.split(":")[1].strip())
                info["pid"] = current
                try:
                    info["exe"] = os.readlink(f"/proc/{current}/exe")
                except OSError:
                    info["exe"] = ""
                chain.append(info)
                current = info.get("ppid", 1)
            except OSError:
                break
        return chain

    def _collect_file_hashes(self, alert: dict) -> list[dict]:
        """Hash files related to the alert."""
        hashes = []
        paths_to_hash = set()

        # Add exe path from alert
        path = alert.get("path", "")
        if path and os.path.isfile(path):
            paths_to_hash.add(path)

        pid = alert.get("pid", 0)
        if pid:
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
                if os.path.isfile(exe):
                    paths_to_hash.add(exe)
            except OSError:
                pass

        for p in paths_to_hash:
            try:
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    for chunk in iter(lambda: f.read(8192), b""):
                        h.update(chunk)
                hashes.append({
                    "path": p,
                    "sha256": h.hexdigest(),
                    "size": os.path.getsize(p),
                })
            except (OSError, PermissionError):
                pass
        return hashes

    def _collect_environ(self, pid: int) -> dict:
        """Collect environment variables (redacted)."""
        env = {}
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                data = f.read()
            for item in data.split(b"\x00"):
                if not item:
                    continue
                try:
                    decoded = item.decode("utf-8", errors="replace")
                    key, _, val = decoded.partition("=")
                    # Redact sensitive values
                    if any(s in key.upper() for s in (
                            "PASSWORD", "SECRET", "TOKEN", "KEY", "PRIVATE")):
                        val = "***REDACTED***"
                    env[key] = val[:200]  # Truncate long values
                except (ValueError, UnicodeDecodeError):
                    pass
        except (OSError, PermissionError):
            pass
        return env

    def _cleanup_old(self):
        """Remove old forensic files (keep last MAX_FORENSIC_FILES)."""
        try:
            files = sorted(FORENSICS_DIR.glob("*.json"),
                          key=lambda p: p.stat().st_mtime)
            while len(files) > MAX_FORENSIC_FILES:
                files.pop(0).unlink()
        except Exception:
            pass

    # ── API helpers ──────────────────────────────────────

    def get_stats(self) -> dict:
        with self._lock:
            files = list(FORENSICS_DIR.glob("*.json"))
            return {
                "total_collections": self._collection_count,
                "stored_evidence": len(files),
                "storage_dir": str(FORENSICS_DIR),
            }

    def get_recent(self, limit: int = 20) -> list[dict]:
        """Get recent forensic evidence summaries."""
        files = sorted(FORENSICS_DIR.glob("*.json"),
                      key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
        summaries = []
        for f in files:
            try:
                with open(f) as fp:
                    data = json.load(fp)
                meta = data.get("metadata", {})
                summaries.append({
                    "file": f.name,
                    "collected_at": meta.get("collected_at", ""),
                    "pid": meta.get("target_pid", 0),
                    "reason": meta.get("trigger_alert", {}).get("reason", ""),
                    "mitre_id": meta.get("trigger_alert", {}).get("mitre_id", ""),
                    "sha256": meta.get("evidence_sha256", "")[:16] + "...",
                })
            except Exception:
                continue
        return summaries
