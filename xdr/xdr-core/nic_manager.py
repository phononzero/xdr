#!/usr/bin/env python3
"""
XDR NIC Manager — Network Interface Auto-Detection & Multi-NIC Support.

Features:
  - Auto-detect default NIC via /proc/net/route
  - Fallback to first UP non-loopback interface via /sys/class/net/
  - List all active NICs with metadata (MAC, IPv4, IPv6, state)
  - NIC validation before XDP attachment
  - Config file override support
"""

import os
import logging
import socket
import struct
from pathlib import Path
from typing import Optional

logger = logging.getLogger("xdr.nic")


def detect_default_nic() -> str:
    """Auto-detect the default network interface.

    Strategy:
      1. Parse /proc/net/route for the default gateway interface
      2. Fallback: first UP, non-loopback interface from /sys/class/net/
      3. Last resort: "eth0"
    """
    # Strategy 1: /proc/net/route default gateway
    try:
        with open("/proc/net/route") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "00000000":
                    iface = parts[0]
                    if validate_nic(iface):
                        logger.info(f"NIC auto-detect: {iface} (default route)")
                        return iface
    except (FileNotFoundError, PermissionError):
        pass

    # Strategy 2: /sys/class/net scan
    try:
        net_dir = Path("/sys/class/net")
        if net_dir.exists():
            for iface_path in sorted(net_dir.iterdir()):
                name = iface_path.name
                if name == "lo":
                    continue
                # Check if UP
                operstate = iface_path / "operstate"
                if operstate.exists():
                    state = operstate.read_text().strip()
                    if state == "up":
                        logger.info(f"NIC auto-detect: {name} (first UP interface)")
                        return name
            # No UP interface found — try any non-loopback
            for iface_path in sorted(net_dir.iterdir()):
                name = iface_path.name
                if name != "lo":
                    logger.warning(f"NIC auto-detect: {name} (first non-lo, may be DOWN)")
                    return name
    except (PermissionError, OSError):
        pass

    # Strategy 3: fallback
    logger.warning("NIC auto-detect failed — falling back to eth0")
    return "eth0"


def get_all_nics() -> list[dict]:
    """Return info for all active network interfaces.

    Returns list of dicts with:
      - name: interface name
      - mac: MAC address
      - ipv4: list of IPv4 addresses
      - ipv6: list of IPv6 addresses
      - state: operstate (up/down/unknown)
      - mtu: MTU size
      - type: interface type (ether, loopback, etc.)
    """
    nics = []
    net_dir = Path("/sys/class/net")
    if not net_dir.exists():
        return nics

    for iface_path in sorted(net_dir.iterdir()):
        name = iface_path.name
        nic_info = {
            "name": name,
            "mac": _read_sys(iface_path / "address"),
            "state": _read_sys(iface_path / "operstate"),
            "mtu": _read_sys_int(iface_path / "mtu"),
            "type": _classify_nic(iface_path),
            "ipv4": [],
            "ipv6": [],
        }

        # Get IP addresses from /proc/net/if_inet6 and ip command
        nic_info["ipv4"] = _get_ipv4_addrs(name)
        nic_info["ipv6"] = _get_ipv6_addrs(name)

        nics.append(nic_info)

    return nics


def validate_nic(name: str) -> bool:
    """Validate that a NIC exists and is in UP state."""
    sys_path = Path(f"/sys/class/net/{name}")
    if not sys_path.exists():
        return False
    operstate = sys_path / "operstate"
    if operstate.exists():
        state = operstate.read_text().strip()
        return state in ("up", "unknown")  # "unknown" for some virtual interfaces
    return True  # Can't determine state — assume valid


def resolve_nic(configured: str) -> str:
    """Resolve NIC name from config value.

    Args:
        configured: Config value — "auto" for auto-detect, or explicit name.

    Returns:
        Resolved NIC name.

    Raises:
        ValueError: If explicit NIC name is invalid.
    """
    if configured.lower() == "auto":
        return detect_default_nic()

    if not validate_nic(configured):
        logger.error(f"Configured NIC '{configured}' not found or DOWN")
        # Try auto-detection as fallback
        fallback = detect_default_nic()
        logger.warning(f"Falling back to auto-detected NIC: {fallback}")
        return fallback

    logger.info(f"Using configured NIC: {configured}")
    return configured


# ── Helper functions ─────────────────────────────────────

def _read_sys(path: Path) -> str:
    """Read a sysfs file, return empty string on failure."""
    try:
        return path.read_text().strip()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def _read_sys_int(path: Path) -> int:
    """Read a sysfs file as int, return 0 on failure."""
    try:
        return int(path.read_text().strip())
    except (FileNotFoundError, PermissionError, OSError, ValueError):
        return 0


def _classify_nic(iface_path: Path) -> str:
    """Classify NIC type (ethernet, loopback, wireless, virtual, etc.)."""
    name = iface_path.name
    if name == "lo":
        return "loopback"
    # Check for wireless
    if (iface_path / "wireless").exists() or (iface_path / "phy80211").exists():
        return "wireless"
    # Check type code
    type_path = iface_path / "type"
    if type_path.exists():
        try:
            type_code = int(type_path.read_text().strip())
            if type_code == 1:
                return "ethernet"
            elif type_code == 772:
                return "loopback"
        except (ValueError, OSError):
            pass
    # Check for virtual
    if (iface_path / "device").exists():
        return "ethernet"  # Has a physical backing device
    return "virtual"


def _get_ipv4_addrs(name: str) -> list[str]:
    """Get IPv4 addresses for a NIC using socket."""
    addrs = []
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # SIOCGIFADDR
        result = fcntl.ioctl(
            s.fileno(), 0x8915,
            struct.pack('256s', name.encode()[:15])
        )
        ip = socket.inet_ntoa(result[20:24])
        addrs.append(ip)
        s.close()
    except (OSError, ImportError):
        pass
    return addrs


def _get_ipv6_addrs(name: str) -> list[str]:
    """Get IPv6 addresses for a NIC from /proc/net/if_inet6."""
    addrs = []
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 6 and parts[5] == name:
                    hex_addr = parts[0]
                    # Format: 32 hex chars → 8 groups of 4
                    groups = [hex_addr[i:i+4] for i in range(0, 32, 4)]
                    ipv6 = ":".join(groups)
                    # Compress with inet_ntop
                    try:
                        packed = socket.inet_pton(socket.AF_INET6, ipv6)
                        compressed = socket.inet_ntop(socket.AF_INET6, packed)
                        addrs.append(compressed)
                    except (OSError, ValueError):
                        addrs.append(ipv6)
    except (FileNotFoundError, PermissionError):
        pass
    return addrs
