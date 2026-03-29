#!/usr/bin/env python3
"""
XDR Integrity Monitor — System binary hash verification (rkhunter replacement).
Tracks SHA256 baselines for critical binaries, detects unauthorized changes,
and correlates with package updates.
"""

import os
import json
import hashlib
import subprocess
import logging
import time
from datetime import datetime
from pathlib import Path
from threading import Thread, Event, Lock

INTEGRITY_DIR = Path("/opt/xdr/integrity")
BASELINES_DIR = INTEGRITY_DIR / "baselines"
DIFFS_DIR = INTEGRITY_DIR / "diffs"
CONFIG_FILE = INTEGRITY_DIR / "config.json"
CURRENT_LINK = INTEGRITY_DIR / "current.json"

DEFAULT_CONFIG = {
    "scan_interval_seconds": 3600,  # 1 hour
    "watch_paths": [
        "/usr/bin/ls", "/usr/bin/ps", "/usr/bin/netstat", "/usr/bin/ss",
        "/usr/bin/cat", "/usr/bin/find", "/usr/bin/grep", "/usr/bin/bash",
        "/usr/bin/sh", "/usr/bin/sudo", "/usr/bin/login", "/usr/bin/ssh",
        "/usr/bin/scp", "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/top",
        "/usr/bin/curl", "/usr/bin/wget", "/usr/bin/python3",
        "/usr/bin/openssl", "/usr/bin/gpg", "/usr/bin/mount",
        "/usr/sbin/sshd", "/usr/sbin/cron",
    ],
    "watch_dirs": [
        "/usr/sbin",
        "/opt/xdr/xdr-core",
    ],
    "watch_globs": [
        "/boot/vmlinuz-*",
        "/boot/initrd*",
    ],
}


def _sha256(path: str) -> str | None:
    """Compute SHA256 of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _file_info(path: str) -> dict | None:
    """Get file metadata + hash."""
    sha = _sha256(path)
    if not sha:
        return None
    try:
        st = os.stat(path)
        # Try to find owning package
        pkg = _get_package_for_file(path)
        return {
            "sha256": sha,
            "size": st.st_size,
            "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
            "permissions": oct(st.st_mode)[-4:],
            "owner": f"{st.st_uid}:{st.st_gid}",
            "package": pkg,
        }
    except OSError:
        return None


def _get_package_for_file(path: str) -> str:
    """Find which dpkg package owns a file."""
    try:
        result = subprocess.run(
            ["dpkg", "-S", path], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip().split(":")[0]
    except Exception:
        pass
    return ""


def _recent_dpkg_changes() -> dict:
    """Parse recent dpkg.log for package changes."""
    changes = {}
    log_path = Path("/var/log/dpkg.log")
    if not log_path.exists():
        return changes
    try:
        with open(log_path) as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[2] in ("install", "upgrade", "remove"):
                    action = parts[2]
                    pkg = parts[3].split(":")[0]
                    changes[pkg] = {"action": action, "date": f"{parts[0]} {parts[1]}"}
    except OSError:
        pass
    return changes


class IntegrityMonitor:
    """System binary integrity monitor."""

    def __init__(self, push_event_fn=None):
        self.push_event = push_event_fn
        self._lock = Lock()
        self._stop = Event()
        self._thread = None
        self._config = dict(DEFAULT_CONFIG)

        # Initialize directories
        for d in (BASELINES_DIR, DIFFS_DIR):
            d.mkdir(parents=True, exist_ok=True)

        self._load_config()

    def _load_config(self):
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE) as f:
                    self._config.update(json.load(f))
        except (json.JSONDecodeError, OSError):
            pass

    def _save_config(self):
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self._config, f, indent=2)
        except OSError as e:
            logging.error(f"Integrity config save error: {e}")

    # ── Scanning ─────────────────────────────────────────

    def _collect_paths(self) -> list[str]:
        """Collect all file paths to monitor."""
        paths = set()
        for p in self._config.get("watch_paths", []):
            if os.path.isfile(p):
                paths.add(p)
        for d in self._config.get("watch_dirs", []):
            if os.path.isdir(d):
                for entry in os.listdir(d):
                    fp = os.path.join(d, entry)
                    if os.path.isfile(fp):
                        paths.add(fp)
        import glob
        for pattern in self._config.get("watch_globs", []):
            paths.update(glob.glob(pattern))
        return sorted(paths)

    def scan(self) -> dict:
        """Scan all watched files and return entries dict."""
        paths = self._collect_paths()
        entries = {}
        for p in paths:
            info = _file_info(p)
            if info:
                entries[p] = info
        return entries

    def initialize_baseline(self) -> dict:
        """Create initial baseline (version 1)."""
        entries = self.scan()
        version = self._next_version()
        now = datetime.now().isoformat()
        baseline = {
            "version": version,
            "created": now,
            "trigger": "initial",
            "kernel": self._get_kernel(),
            "file_count": len(entries),
            "entries": entries,
        }
        self._save_baseline(version, baseline)
        return {"version": version, "file_count": len(entries)}

    def run_scan(self) -> dict:
        """Run incremental scan against current baseline (NO auto-baseline update)."""
        current = self._load_current()
        if not current:
            return self.initialize_baseline()

        new_entries = self.scan()
        old_entries = current.get("entries", {})

        diff = self._compute_diff(old_entries, new_entries)

        if not diff["modified"] and not diff["added"] and not diff["removed"]:
            return {"status": "clean", "version": current["version"],
                    "file_count": len(new_entries)}

        # Check if changes are explained by dpkg
        dpkg = _recent_dpkg_changes()
        unexplained = []
        for path, change in diff["modified"].items():
            pkg = old_entries.get(path, {}).get("package", "")
            if pkg and pkg in dpkg:
                change["explained"] = True
                change["reason"] = f"패키지 업데이트: {pkg} ({dpkg[pkg]['action']})"
            else:
                change["explained"] = False
                change["reason"] = "설명 불가 — 잠재적 변조"
                unexplained.append(path)

        # Save diff record (but do NOT create new baseline)
        diff_record = {
            "base_version": current["version"],
            "date": datetime.now().isoformat(),
            "trigger": "scan",
            "changes": diff,
            "new_entries": new_entries,  # Store for manual approval
        }
        diff_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_scan.json"
        with open(DIFFS_DIR / diff_name, "w") as f:
            json.dump(diff_record, f, indent=2, ensure_ascii=False)

        # Alert for unexplained changes
        if unexplained and self.push_event:
            self.push_event({
                "source": "INTEGRITY",
                "action": "ALERT",
                "reason": "UNEXPLAINED_CHANGE",
                "detail": f"설명 불가 파일 변조 {len(unexplained)}건: "
                         + ", ".join(unexplained[:5]),
                "alert_level": 3,
                "files": unexplained,
            })

        return {
            "status": "changed",
            "version": current["version"],  # Still on same baseline
            "modified": len(diff["modified"]),
            "added": len(diff["added"]),
            "removed": len(diff["removed"]),
            "unexplained": len(unexplained),
            "baseline_updated": False,  # Explicit: baseline NOT updated
        }

    def _compute_diff(self, old: dict, new: dict) -> dict:
        modified, added, removed = {}, {}, {}
        for path, info in new.items():
            if path not in old:
                added[path] = info
            elif info["sha256"] != old[path]["sha256"]:
                modified[path] = {
                    "old_hash": old[path]["sha256"],
                    "new_hash": info["sha256"],
                }
        for path in old:
            if path not in new:
                removed[path] = old[path]
        return {"modified": modified, "added": added, "removed": removed}

    # ── Persistence ──────────────────────────────────────

    def _next_version(self) -> int:
        current = self._load_current()
        return (current["version"] + 1) if current else 1

    def _save_baseline(self, version: int, data: dict):
        name = f"{datetime.now().strftime('%Y-%m-%d')}_v{version}.json"
        path = BASELINES_DIR / name
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        # Update current symlink
        if CURRENT_LINK.is_symlink() or CURRENT_LINK.exists():
            CURRENT_LINK.unlink()
        CURRENT_LINK.symlink_to(path)

    def _load_current(self) -> dict | None:
        try:
            if CURRENT_LINK.exists():
                with open(CURRENT_LINK) as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
        return None

    def get_status(self) -> dict:
        current = self._load_current()
        baselines = sorted(BASELINES_DIR.glob("*.json"))
        diffs = sorted(DIFFS_DIR.glob("*.json"))
        return {
            "current_version": current["version"] if current else 0,
            "file_count": current.get("file_count", 0) if current else 0,
            "baseline_count": len(baselines),
            "diff_count": len(diffs),
            "last_scan": current.get("created", "") if current else "",
            "kernel": current.get("kernel", "") if current else "",
        }

    def get_baselines(self) -> list[dict]:
        result = []
        for f in sorted(BASELINES_DIR.glob("*.json")):
            try:
                with open(f) as fh:
                    data = json.load(fh)
                result.append({
                    "file": f.name,
                    "version": data.get("version"),
                    "created": data.get("created"),
                    "trigger": data.get("trigger"),
                    "file_count": data.get("file_count", len(data.get("entries", {}))),
                })
            except (json.JSONDecodeError, OSError):
                pass
        return result

    def get_diffs(self) -> list[dict]:
        result = []
        for f in sorted(DIFFS_DIR.glob("*.json")):
            try:
                with open(f) as fh:
                    data = json.load(fh)
                changes = data.get("changes", {})
                result.append({
                    "file": f.name,
                    "from_version": data.get("from_version"),
                    "to_version": data.get("to_version"),
                    "date": data.get("date"),
                    "modified": len(changes.get("modified", {})),
                    "added": len(changes.get("added", {})),
                    "removed": len(changes.get("removed", {})),
                })
            except (json.JSONDecodeError, OSError):
                pass
        return result

    @staticmethod
    def _get_kernel() -> str:
        try:
            return subprocess.run(
                ["uname", "-r"], capture_output=True, text=True, timeout=5
            ).stdout.strip()
        except Exception:
            return ""

    # ── Background thread ────────────────────────────────

    def start(self):
        self._thread = Thread(target=self._loop, daemon=True, name="integrity")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        # Initial baseline if none exists
        if not self._load_current():
            logging.info("Integrity: creating initial baseline...")
            result = self.initialize_baseline()
            logging.info(f"Integrity: baseline v{result['version']} "
                        f"({result['file_count']} files)")

        interval = self._config.get("scan_interval_seconds", 3600)
        while not self._stop.wait(interval):
            try:
                result = self.run_scan()
                logging.info(f"Integrity scan: {result.get('status', 'unknown')}")
            except Exception as e:
                logging.error(f"Integrity scan error: {e}")
