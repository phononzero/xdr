#!/usr/bin/env python3
"""
XDR Package Monitor — Package list versioning and change tracking.
Maintains versioned snapshots of installed packages, detects additions/removals,
and correlates with dpkg.log for anomaly detection.
"""

import json
import subprocess
import logging
import time
from datetime import datetime
from pathlib import Path
from threading import Thread, Event

PACKAGES_DIR = Path("/opt/xdr/packages")
SNAPSHOTS_DIR = PACKAGES_DIR / "snapshots"
DIFFS_DIR = PACKAGES_DIR / "diffs"
CONFIG_FILE = PACKAGES_DIR / "config.json"
CURRENT_LINK = PACKAGES_DIR / "current.json"

DEFAULT_CONFIG = {
    "scan_interval_seconds": 21600,  # 6 hours
    "ignore_packages": [],           # packages to exclude from alerts
}


def _get_installed_packages() -> dict:
    """Get all installed packages via dpkg-query."""
    packages = {}
    try:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f",
             "${Package}\t${Version}\t${Architecture}\t${Status}\n"],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 4 and "installed" in parts[3]:
                packages[parts[0]] = {
                    "version": parts[1],
                    "arch": parts[2],
                    "status": "installed",
                }
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        logging.error(f"Package query error: {e}")
    return packages


def _parse_dpkg_log() -> list[dict]:
    """Parse dpkg.log for recent operations."""
    entries = []
    for log_path in [
        Path("/var/log/dpkg.log"),
        Path("/var/log/dpkg.log.1"),
    ]:
        if not log_path.exists():
            continue
        try:
            with open(log_path) as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        action = parts[2]
                        if action in ("install", "upgrade", "remove",
                                      "purge", "configure"):
                            pkg = parts[3].split(":")[0]
                            ver = parts[4] if len(parts) > 4 else ""
                            entries.append({
                                "date": f"{parts[0]} {parts[1]}",
                                "action": action,
                                "package": pkg,
                                "version": ver,
                            })
        except OSError:
            pass
    return entries


class PackageMonitor:
    """Package list versioning and change tracker."""

    def __init__(self, push_event_fn=None):
        self.push_event = push_event_fn
        self._stop = Event()
        self._thread = None
        self._config = dict(DEFAULT_CONFIG)

        for d in (SNAPSHOTS_DIR, DIFFS_DIR):
            d.mkdir(parents=True, exist_ok=True)
        self._load_config()

    def _load_config(self):
        try:
            if CONFIG_FILE.exists():
                with open(CONFIG_FILE) as f:
                    self._config.update(json.load(f))
        except (json.JSONDecodeError, OSError):
            pass

    # ── Scanning ─────────────────────────────────────────

    def scan(self) -> dict:
        """Get current installed packages."""
        return _get_installed_packages()

    def initialize_snapshot(self) -> dict:
        """Create initial snapshot (version 1)."""
        packages = self.scan()
        version = self._next_version()
        snapshot = {
            "version": version,
            "created": datetime.now().isoformat(),
            "trigger": "initial",
            "total_packages": len(packages),
            "packages": packages,
        }
        self._save_snapshot(version, snapshot)
        return {"version": version, "total_packages": len(packages)}

    def run_scan(self) -> dict:
        """Run incremental scan against current snapshot."""
        current = self._load_current()
        if not current:
            return self.initialize_snapshot()

        new_pkgs = self.scan()
        old_pkgs = current.get("packages", {})
        ignore = set(self._config.get("ignore_packages", []))

        diff = self._compute_diff(old_pkgs, new_pkgs, ignore)

        if not diff["added"] and not diff["removed"] and not diff["upgraded"]:
            return {"status": "unchanged", "version": current["version"],
                    "total_packages": len(new_pkgs)}

        # Save new snapshot
        version = self._next_version()
        snapshot = {
            "version": version,
            "created": datetime.now().isoformat(),
            "trigger": "scan",
            "total_packages": len(new_pkgs),
            "packages": new_pkgs,
        }
        self._save_snapshot(version, snapshot)

        # Save diff
        diff_record = {
            "from_version": current["version"],
            "to_version": version,
            "date": datetime.now().isoformat(),
            "added": diff["added"],
            "removed": diff["removed"],
            "upgraded": diff["upgraded"],
            "downgraded": diff["downgraded"],
        }
        diff_name = (f"{datetime.now().strftime('%Y-%m-%d')}_"
                     f"v{current['version']}→v{version}.json")
        with open(DIFFS_DIR / diff_name, "w") as f:
            json.dump(diff_record, f, indent=2, ensure_ascii=False)

        # Alert for suspicious changes
        if diff["downgraded"] and self.push_event:
            self.push_event({
                "source": "PACKAGE",
                "action": "ALERT",
                "reason": "PACKAGE_DOWNGRADE",
                "detail": f"패키지 다운그레이드 감지: "
                         + ", ".join(f"{k} ({v['old']}→{v['new']})"
                                     for k, v in diff["downgraded"].items()),
                "alert_level": 3,
            })

        if diff["added"] and self.push_event:
            # Check if added packages are from unexpected sources
            dpkg_log = _parse_dpkg_log()
            recent_installs = {e["package"] for e in dpkg_log
                             if e["action"] == "install"}
            unexpected = [p for p in diff["added"]
                         if p not in recent_installs and p not in ignore]
            if unexpected:
                self.push_event({
                    "source": "PACKAGE",
                    "action": "ALERT",
                    "reason": "UNEXPECTED_PACKAGE",
                    "detail": f"예상치 못한 패키지 설치: {', '.join(unexpected[:10])}",
                    "alert_level": 2,
                })

        return {
            "status": "changed",
            "version": version,
            "total_packages": len(new_pkgs),
            "added": len(diff["added"]),
            "removed": len(diff["removed"]),
            "upgraded": len(diff["upgraded"]),
            "downgraded": len(diff["downgraded"]),
        }

    def _compute_diff(self, old: dict, new: dict, ignore: set) -> dict:
        added, removed, upgraded, downgraded = {}, {}, {}, {}

        for pkg, info in new.items():
            if pkg in ignore:
                continue
            if pkg not in old:
                added[pkg] = info
            elif info["version"] != old[pkg]["version"]:
                try:
                    cmp = self._compare_versions(
                        old[pkg]["version"], info["version"])
                    if cmp > 0:  # old > new = downgrade
                        downgraded[pkg] = {"old": old[pkg]["version"],
                                           "new": info["version"]}
                    else:
                        upgraded[pkg] = {"old": old[pkg]["version"],
                                         "new": info["version"]}
                except Exception:
                    upgraded[pkg] = {"old": old[pkg]["version"],
                                     "new": info["version"]}

        for pkg in old:
            if pkg not in new and pkg not in ignore:
                removed[pkg] = old[pkg]

        return {"added": added, "removed": removed,
                "upgraded": upgraded, "downgraded": downgraded}

    @staticmethod
    def _compare_versions(v1: str, v2: str) -> int:
        """Compare two dpkg-style version strings.
        Returns: >0 if v1>v2, <0 if v1<v2, 0 if equal."""
        import re
        def _parse(v: str) -> list:
            # Strip epoch (1:xxx -> xxx)
            if ":" in v:
                v = v.split(":", 1)[1]
            # Split into numeric and non-numeric parts
            return [int(x) if x.isdigit() else x
                    for x in re.split(r'(\d+)', v) if x]

        p1, p2 = _parse(v1), _parse(v2)
        for a, b in zip(p1, p2):
            if type(a) == type(b):
                if a < b: return -1
                if a > b: return 1
            else:
                # numeric > string
                if isinstance(a, int): return 1
                return -1
        return len(p1) - len(p2)

    # ── Persistence ──────────────────────────────────────

    def _next_version(self) -> int:
        current = self._load_current()
        return (current["version"] + 1) if current else 1

    def _save_snapshot(self, version: int, data: dict):
        name = f"{datetime.now().strftime('%Y-%m-%d')}_v{version}.json"
        path = SNAPSHOTS_DIR / name
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
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

    # ── API helpers ──────────────────────────────────────

    def get_status(self) -> dict:
        current = self._load_current()
        return {
            "current_version": current["version"] if current else 0,
            "total_packages": current.get("total_packages", 0) if current else 0,
            "snapshot_count": len(list(SNAPSHOTS_DIR.glob("*.json"))),
            "diff_count": len(list(DIFFS_DIR.glob("*.json"))),
            "last_scan": current.get("created", "") if current else "",
        }

    def get_snapshots(self) -> list[dict]:
        result = []
        for f in sorted(SNAPSHOTS_DIR.glob("*.json")):
            try:
                with open(f) as fh:
                    data = json.load(fh)
                result.append({
                    "file": f.name,
                    "version": data.get("version"),
                    "created": data.get("created"),
                    "trigger": data.get("trigger"),
                    "total_packages": data.get("total_packages"),
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
                result.append({
                    "file": f.name,
                    "from_version": data.get("from_version"),
                    "to_version": data.get("to_version"),
                    "date": data.get("date"),
                    "added": len(data.get("added", {})),
                    "removed": len(data.get("removed", {})),
                    "upgraded": len(data.get("upgraded", {})),
                    "downgraded": len(data.get("downgraded", {})),
                })
            except (json.JSONDecodeError, OSError):
                pass
        return result

    def get_timeline(self) -> list[dict]:
        """Get all changes as a timeline."""
        timeline = []
        for f in sorted(DIFFS_DIR.glob("*.json")):
            try:
                with open(f) as fh:
                    data = json.load(fh)
                for pkg, info in data.get("added", {}).items():
                    timeline.append({
                        "date": data["date"], "action": "install",
                        "package": pkg, "version": info.get("version", ""),
                    })
                for pkg, info in data.get("removed", {}).items():
                    timeline.append({
                        "date": data["date"], "action": "remove",
                        "package": pkg, "version": info.get("version", ""),
                    })
                for pkg, info in data.get("upgraded", {}).items():
                    timeline.append({
                        "date": data["date"], "action": "upgrade",
                        "package": pkg,
                        "version": f"{info['old']}→{info['new']}",
                    })
                for pkg, info in data.get("downgraded", {}).items():
                    timeline.append({
                        "date": data["date"], "action": "downgrade",
                        "package": pkg,
                        "version": f"{info['old']}→{info['new']}",
                    })
            except (json.JSONDecodeError, OSError):
                pass
        return sorted(timeline, key=lambda x: x["date"], reverse=True)

    # ── Background thread ────────────────────────────────

    def start(self):
        self._thread = Thread(target=self._loop, daemon=True, name="packages")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        if not self._load_current():
            logging.info("Package monitor: creating initial snapshot...")
            result = self.initialize_snapshot()
            logging.info(f"Package monitor: snapshot v{result['version']} "
                        f"({result['total_packages']} packages)")

        interval = self._config.get("scan_interval_seconds", 21600)
        while not self._stop.wait(interval):
            try:
                result = self.run_scan()
                logging.info(f"Package scan: {result.get('status', 'unknown')}")
            except Exception as e:
                logging.error(f"Package scan error: {e}")
