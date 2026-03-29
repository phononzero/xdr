#!/usr/bin/env python3
"""
XDR Asset Policy — Whitelist/Blacklist Management.

Manages allow/deny lists for kernel modules, packages, and hardware.
Persisted as YAML at /opt/xdr/xdr-core/asset_policy.yaml.
"""

import logging
from pathlib import Path
from threading import Lock

import yaml

logger = logging.getLogger("xdr.policy")

POLICY_FILE = Path("/opt/xdr/xdr-core/asset_policy.yaml")
POLICY_FILE_DEV = Path(__file__).parent / "asset_policy.yaml"

DEFAULT_POLICY = {
    "modules": {
        "whitelist": [],
        "blacklist": [],
    },
    "packages": {
        "whitelist": [],
        "blacklist": [],
    },
    "hardware": {
        "whitelist": [],   # [{"vendor": "...", "product": "...", "name": "..."}]
        "blacklist": [],
    },
}


class AssetPolicy:
    """Thread-safe whitelist/blacklist manager with YAML persistence."""

    def __init__(self):
        self._lock = Lock()
        self._policy = {}
        self._load()

    def _get_path(self) -> Path:
        if POLICY_FILE.exists():
            return POLICY_FILE
        return POLICY_FILE_DEV

    def _load(self):
        path = self._get_path()
        try:
            if path.exists():
                with open(path) as f:
                    self._policy = yaml.safe_load(f) or {}
            # Ensure all sections exist
            for section in ("modules", "packages", "hardware"):
                if section not in self._policy:
                    self._policy[section] = {"whitelist": [], "blacklist": []}
                for lst in ("whitelist", "blacklist"):
                    if lst not in self._policy[section]:
                        self._policy[section][lst] = []
            logger.info(f"Asset policy loaded from {path}")
        except Exception as e:
            logger.warning(f"Policy load error: {e}, using defaults")
            self._policy = DEFAULT_POLICY.copy()

    def _save(self):
        path = self._get_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w") as f:
                yaml.dump(self._policy, f, default_flow_style=False,
                          allow_unicode=True)
        except Exception as e:
            logger.error(f"Policy save error: {e}")

    # ── Query ────────────────────────────────────────────

    def get_all(self) -> dict:
        with self._lock:
            return dict(self._policy)

    def get_section(self, section: str) -> dict:
        with self._lock:
            return dict(self._policy.get(section, {"whitelist": [], "blacklist": []}))

    def is_whitelisted(self, section: str, name: str) -> bool:
        with self._lock:
            wl = self._policy.get(section, {}).get("whitelist", [])
            if section == "hardware":
                return any(h.get("name") == name or
                           f"{h.get('vendor', '')}:{h.get('product', '')}" == name
                           for h in wl)
            return name in wl

    def is_blacklisted(self, section: str, name: str) -> bool:
        with self._lock:
            bl = self._policy.get(section, {}).get("blacklist", [])
            if section == "hardware":
                return any(h.get("name") == name or
                           f"{h.get('vendor', '')}:{h.get('product', '')}" == name
                           for h in bl)
            return name in bl

    # ── Modify ───────────────────────────────────────────

    def add_to_whitelist(self, section: str, item) -> dict:
        with self._lock:
            wl = self._policy[section]["whitelist"]
            bl = self._policy[section]["blacklist"]

            # Remove from blacklist if present
            if section == "hardware":
                key = item if isinstance(item, dict) else {"name": item}
                bl[:] = [h for h in bl
                         if h.get("name") != key.get("name")]
                if not any(h.get("name") == key.get("name") for h in wl):
                    wl.append(key)
            else:
                if item in bl:
                    bl.remove(item)
                if item not in wl:
                    wl.append(item)

            self._save()
            return {"ok": True, "message": f"'{item}' → 화이트리스트 추가"}

    def add_to_blacklist(self, section: str, item) -> dict:
        with self._lock:
            wl = self._policy[section]["whitelist"]
            bl = self._policy[section]["blacklist"]

            if section == "hardware":
                key = item if isinstance(item, dict) else {"name": item}
                wl[:] = [h for h in wl
                         if h.get("name") != key.get("name")]
                if not any(h.get("name") == key.get("name") for h in bl):
                    bl.append(key)
            else:
                if item in wl:
                    wl.remove(item)
                if item not in bl:
                    bl.append(item)

            self._save()
            return {"ok": True, "message": f"'{item}' → 블랙리스트 추가"}

    def remove_from_list(self, section: str, list_type: str, item) -> dict:
        with self._lock:
            lst = self._policy[section].get(list_type, [])
            if section == "hardware":
                name = item if isinstance(item, str) else item.get("name", "")
                lst[:] = [h for h in lst if h.get("name") != name]
            else:
                if item in lst:
                    lst.remove(item)

            self._save()
            return {"ok": True, "message": f"'{item}' → {list_type}에서 제거"}


# Singleton
_instance = None

def get_policy() -> AssetPolicy:
    global _instance
    if _instance is None:
        _instance = AssetPolicy()
    return _instance
