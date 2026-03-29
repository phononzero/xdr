#!/usr/bin/env python3
"""
XDR Blocklist Store — Persistent blocklist management.
Saves/loads blocklists from JSON on disk and syncs to BPF maps via bpftool.

CIDR blocking is implemented via nftables (table inet block_c2_asn),
because BPF hash maps do not support prefix-length matching.
All CIDR entries are persisted in blocklists.json under 'blocked_cidrs'.
"""

import ipaddress
import json
import struct
import socket
import subprocess
import logging
from pathlib import Path
from threading import Lock

CONFIG_DIR = Path("/opt/xdr/config")
BLOCKLIST_FILE = CONFIG_DIR / "blocklists.json"
NFT_TABLE = "inet block_c2_asn"
NFT_CHAIN = "output"

DEFAULT_STATE = {
    "blocked_ips": [],       # NDR: packet DROP
    "blocked_ports": [],     # NDR: packet DROP
    "blocked_pids": [],      # EDR: SIGKILL on exec
    "edr_watch_ips": [],     # EDR: CRITICAL alert (no drop)
    "known_macs": {},        # NDR: ARP spoof detection {"ip": "mac"}
    "blocked_paths": [],     # EDR: path/wildcard block (permanent)
    "blocked_hashes": [],    # EDR: SHA256 block [{"hash":...,"name":...,"reason":...}]
    "blocked_cidrs": [],     # NDR: nftables CIDR drop [{"cidr":...,"asn":...,"label":...,"reason":...}]
}


class BlocklistStore:
    """Thread-safe persistent blocklist manager."""

    def __init__(self):
        self._lock = Lock()
        self._data = dict(DEFAULT_STATE)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self._load()

    # ── Persistence ──────────────────────────────────────

    def _load(self):
        """Load blocklists from disk."""
        if BLOCKLIST_FILE.exists():
            try:
                with open(BLOCKLIST_FILE, "r") as f:
                    saved = json.load(f)
                for key in DEFAULT_STATE:
                    if key in saved:
                        self._data[key] = saved[key]
                logging.info(f"Blocklists loaded from {BLOCKLIST_FILE}")
            except (json.JSONDecodeError, OSError) as e:
                logging.warning(f"Failed to load blocklists: {e}")
        else:
            self._save()

    def _save(self):
        """Save blocklists to disk."""
        try:
            with open(BLOCKLIST_FILE, "w") as f:
                json.dump(self._data, f, indent=2)
        except OSError as e:
            logging.error(f"Failed to save blocklists: {e}")

    # ── Getters ──────────────────────────────────────────

    def get_all(self) -> dict:
        with self._lock:
            return dict(self._data)

    def get(self, list_type: str) -> list | dict:
        with self._lock:
            return self._data.get(list_type, [])

    # ── IP Management ────────────────────────────────────

    def add_blocked_ip(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._data["blocked_ips"]:
                self._data["blocked_ips"].append(ip)
                self._save()
                self._bpf_map_add_ip("ndr_blocked_ips", ip)
                return True
            return False

    def remove_blocked_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self._data["blocked_ips"]:
                self._data["blocked_ips"].remove(ip)
                self._save()
                self._bpf_map_del_ip("ndr_blocked_ips", ip)
                return True
            return False

    def add_edr_watch_ip(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._data["edr_watch_ips"]:
                self._data["edr_watch_ips"].append(ip)
                self._save()
                self._bpf_map_add_ip("blocked_ips", ip)
                return True
            return False

    def remove_edr_watch_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self._data["edr_watch_ips"]:
                self._data["edr_watch_ips"].remove(ip)
                self._save()
                self._bpf_map_del_ip("blocked_ips", ip)
                return True
            return False

    # ── Port Management ──────────────────────────────────

    def add_blocked_port(self, port: int) -> bool:
        with self._lock:
            if port not in self._data["blocked_ports"]:
                self._data["blocked_ports"].append(port)
                self._save()
                self._bpf_map_add_port("ndr_blocked_por", port)
                return True
            return False

    def remove_blocked_port(self, port: int) -> bool:
        with self._lock:
            if port in self._data["blocked_ports"]:
                self._data["blocked_ports"].remove(port)
                self._save()
                self._bpf_map_del_port("ndr_blocked_por", port)
                return True
            return False

    # ── PID Management ───────────────────────────────────

    def add_blocked_pid(self, pid: int) -> bool:
        with self._lock:
            if pid not in self._data["blocked_pids"]:
                self._data["blocked_pids"].append(pid)
                self._save()
                self._bpf_map_add_u32("blocked_pids", pid)
                return True
            return False

    def remove_blocked_pid(self, pid: int) -> bool:
        with self._lock:
            if pid in self._data["blocked_pids"]:
                self._data["blocked_pids"].remove(pid)
                self._save()
                self._bpf_map_del_u32("blocked_pids", pid)
                return True
            return False

    # ── MAC Management ───────────────────────────────────

    def add_known_mac(self, ip: str, mac: str) -> bool:
        with self._lock:
            self._data["known_macs"][ip] = mac
            self._save()
            self._bpf_map_add_mac("known_macs", ip, mac)
            return True

    def remove_known_mac(self, ip: str) -> bool:
        with self._lock:
            if ip in self._data["known_macs"]:
                del self._data["known_macs"][ip]
                self._save()
                self._bpf_map_del_ip("known_macs", ip)
                return True
            return False

    # ── Path Management ───────────────────────────────────

    def add_blocked_path(self, path: str) -> bool:
        with self._lock:
            if path not in self._data["blocked_paths"]:
                self._data["blocked_paths"].append(path)
                self._save()
                return True
            return False

    def remove_blocked_path(self, path: str) -> bool:
        with self._lock:
            if path in self._data["blocked_paths"]:
                self._data["blocked_paths"].remove(path)
                self._save()
                return True
            return False

    # ── Hash Management ──────────────────────────────────

    def add_blocked_hash(self, sha256: str, name: str = "", reason: str = "") -> bool:
        with self._lock:
            for entry in self._data["blocked_hashes"]:
                if entry.get("hash") == sha256:
                    return False
            self._data["blocked_hashes"].append({
                "hash": sha256, "name": name, "reason": reason
            })
            self._save()
            return True

    def remove_blocked_hash(self, sha256: str) -> bool:
        with self._lock:
            before = len(self._data["blocked_hashes"])
            self._data["blocked_hashes"] = [
                e for e in self._data["blocked_hashes"]
                if e.get("hash") != sha256
            ]
            if len(self._data["blocked_hashes"]) < before:
                self._save()
                return True
            return False

    # ── CIDR Management (nftables) ───────────────────────

    def add_blocked_cidr(self, cidr: str, asn: str = "", label: str = "", reason: str = "") -> bool:
        """Add a CIDR block via nftables and persist to config."""
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logging.warning(f"Invalid CIDR: {cidr}")
            return False
        with self._lock:
            exists = any(e.get("cidr") == cidr for e in self._data["blocked_cidrs"])
            if not exists:
                self._data["blocked_cidrs"].append({
                    "cidr": cidr, "asn": asn, "label": label, "reason": reason
                })
                self._save()
            if self._nft_add_cidr(cidr):
                logging.info(f"CIDR blocked: {cidr} ({label or asn})")
                return True
            return not exists

    def remove_blocked_cidr(self, cidr: str) -> bool:
        """Remove a CIDR block from nftables and config."""
        with self._lock:
            before = len(self._data["blocked_cidrs"])
            self._data["blocked_cidrs"] = [
                e for e in self._data["blocked_cidrs"] if e.get("cidr") != cidr
            ]
            if len(self._data["blocked_cidrs"]) < before:
                self._save()
                self._nft_del_cidr(cidr)
                logging.info(f"CIDR unblocked: {cidr}")
                return True
            return False

    def get_blocked_cidrs(self) -> list:
        with self._lock:
            return list(self._data.get("blocked_cidrs", []))

    def _nft_ensure_table(self):
        """Ensure nftables table and chain exist."""
        subprocess.run(
            ["nft", "add", "table"] + NFT_TABLE.split(),
            capture_output=True
        )
        subprocess.run(
            ["nft", "add", "chain"] + NFT_TABLE.split() + [
                NFT_CHAIN, "{ type filter hook output priority 0; policy accept; }"
            ],
            capture_output=True
        )

    def _nft_add_cidr(self, cidr: str) -> bool:
        self._nft_ensure_table()
        # Avoid duplicate rules
        result = subprocess.run(
            ["nft", "list", "table"] + NFT_TABLE.split(),
            capture_output=True, text=True
        )
        if cidr in result.stdout:
            return True  # already present
        r = subprocess.run(
            ["nft", "add", "rule"] + NFT_TABLE.split() + [
                NFT_CHAIN, "ip", "daddr", cidr, "drop"
            ],
            capture_output=True
        )
        return r.returncode == 0

    def _nft_del_cidr(self, cidr: str):
        """Remove all rules matching this CIDR from the table."""
        result = subprocess.run(
            ["nft", "-a", "list", "table"] + NFT_TABLE.split(),
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if cidr in line and "handle" in line:
                try:
                    handle = line.strip().split("handle")[-1].strip()
                    subprocess.run(
                        ["nft", "delete", "rule"] + NFT_TABLE.split() +
                        [NFT_CHAIN, "handle", handle],
                        capture_output=True
                    )
                except Exception:
                    pass

    def _sync_cidrs_to_nftables(self):
        """Apply all blocked_cidrs from config to nftables at startup."""
        cidrs = self._data.get("blocked_cidrs", [])
        if not cidrs:
            return
        self._nft_ensure_table()
        # Get existing rules to avoid duplicates
        result = subprocess.run(
            ["nft", "list", "table"] + NFT_TABLE.split(),
            capture_output=True, text=True
        )
        existing = result.stdout
        count = 0
        for entry in cidrs:
            cidr = entry.get("cidr", "")
            if not cidr:
                continue
            if cidr not in existing:
                self._nft_add_cidr(cidr)
                count += 1
        logging.info(f"CIDR sync: {count} new rules applied ({len(cidrs)} total configured)")

    # ── Sync all to BPF maps ─────────────────────────────

    def sync_to_bpf(self):
        """Push all blocklist entries to BPF maps + nftables. Called at startup."""
        logging.info("Syncing blocklists to BPF maps...")

        for ip in self._data.get("blocked_ips", []):
            self._bpf_map_add_ip("ndr_blocked_ips", ip)

        for ip in self._data.get("edr_watch_ips", []):
            self._bpf_map_add_ip("blocked_ips", ip)

        for port in self._data.get("blocked_ports", []):
            self._bpf_map_add_port("ndr_blocked_por", port)

        for pid in self._data.get("blocked_pids", []):
            self._bpf_map_add_u32("blocked_pids", pid)

        for ip, mac in self._data.get("known_macs", {}).items():
            self._bpf_map_add_mac("known_macs", ip, mac)

        # CIDR blocks → nftables
        self._sync_cidrs_to_nftables()

        logging.info("Blocklist sync complete")

    # ── BPF map helpers ──────────────────────────────────

    @staticmethod
    def _ip_to_hex(ip: str) -> str:
        """Convert IP to hex key string for bpftool."""
        packed = struct.pack("!I", struct.unpack("!I", socket.inet_aton(ip))[0])
        return " ".join(f"{b:02x}" for b in packed)

    @staticmethod
    def _bpftool(*args) -> bool:
        try:
            subprocess.run(
                ["bpftool"] + list(args),
                check=True, capture_output=True, timeout=5
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            logging.debug(f"bpftool {' '.join(args)}: {e}")
            return False

    def _bpf_map_add_ip(self, map_name: str, ip: str):
        hex_key = self._ip_to_hex(ip)
        self._bpftool("map", "update", "name", map_name,
                       "key", "hex", *hex_key.split(), "value", "hex", "01")

    def _bpf_map_del_ip(self, map_name: str, ip: str):
        hex_key = self._ip_to_hex(ip)
        self._bpftool("map", "delete", "name", map_name,
                       "key", "hex", *hex_key.split())

    def _bpf_map_add_port(self, map_name: str, port: int):
        # Port stored as 2-byte big-endian
        hex_key = f"{(port >> 8) & 0xff:02x} {port & 0xff:02x}"
        self._bpftool("map", "update", "name", map_name,
                       "key", "hex", *hex_key.split(), "value", "hex", "01")

    def _bpf_map_del_port(self, map_name: str, port: int):
        hex_key = f"{(port >> 8) & 0xff:02x} {port & 0xff:02x}"
        self._bpftool("map", "delete", "name", map_name,
                       "key", "hex", *hex_key.split())

    def _bpf_map_add_u32(self, map_name: str, val: int):
        # Little-endian u32
        packed = struct.pack("<I", val)
        hex_key = " ".join(f"{b:02x}" for b in packed)
        self._bpftool("map", "update", "name", map_name,
                       "key", "hex", *hex_key.split(), "value", "hex", "01")

    def _bpf_map_del_u32(self, map_name: str, val: int):
        packed = struct.pack("<I", val)
        hex_key = " ".join(f"{b:02x}" for b in packed)
        self._bpftool("map", "delete", "name", map_name,
                       "key", "hex", *hex_key.split())

    def _bpf_map_add_mac(self, map_name: str, ip: str, mac: str):
        hex_key = self._ip_to_hex(ip)
        mac_bytes = mac.replace(":", " ")
        # struct mac_entry = 6 bytes mac + 2 bytes pad
        hex_val = f"{mac_bytes} 00 00"
        self._bpftool("map", "update", "name", map_name,
                       "key", "hex", *hex_key.split(),
                       "value", "hex", *hex_val.split())
