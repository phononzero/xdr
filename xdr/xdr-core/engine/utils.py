"""
XDR Engine utility functions.
"""

import struct
import socket


def ip_str(ip_int: int) -> str:
    """Convert a 32-bit integer IP to dotted string (IPv4)."""
    if ip_int == 0:
        return "0.0.0.0"
    try:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    except (struct.error, OSError):
        return f"0x{ip_int:08x}"


def ip_str6(ip_bytes: bytes | int) -> str:
    """Convert 16 bytes (or 128-bit int) to IPv6 string."""
    if isinstance(ip_bytes, int):
        ip_bytes = ip_bytes.to_bytes(16, byteorder="big")
    if len(ip_bytes) != 16:
        return "::"
    if ip_bytes == b'\x00' * 16:
        return "::"
    try:
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    except (OSError, ValueError):
        return "::"


def ip_str_auto(value: int | bytes, version: int = 4) -> str:
    """Auto-detect and convert IP address based on version."""
    if version == 6:
        return ip_str6(value)
    return ip_str(value if isinstance(value, int) else int.from_bytes(value, "big"))


def is_ipv6(addr: str) -> bool:
    """Check if a string is a valid IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except (OSError, ValueError):
        return False


def is_ipv4(addr: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    try:
        socket.inet_pton(socket.AF_INET, addr)
        return True
    except (OSError, ValueError):
        return False


def normalize_ip(addr: str) -> str:
    """Normalize an IP address string (compress IPv6, validate IPv4)."""
    if is_ipv6(addr):
        packed = socket.inet_pton(socket.AF_INET6, addr)
        return socket.inet_ntop(socket.AF_INET6, packed)
    if is_ipv4(addr):
        return addr
    return addr

