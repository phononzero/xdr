#!/usr/bin/env python3
"""
XDR TLS Fingerprint — JA3/JA3S TLS fingerprinting.

Parses TLS ClientHello from captured packets to generate JA3 hashes.
Compares against known malicious fingerprints database.
"""

import hashlib
import struct
import logging
import json
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from threading import Thread, Event, Lock

TLS_DATA_DIR = Path("/opt/xdr/tls")

# ── Known malicious JA3 hashes ──────────────────────────
# Source: ja3er.com + abuse.ch SSL blacklist
KNOWN_MALICIOUS_JA3 = {
    # Cobalt Strike
    "72a589da586844d7f0818ce684948eea": "CobaltStrike",
    "a0e9f5d64349fb13191bc781f81f42e1": "CobaltStrike",
    "b742b407517bac9536a77a7b0fee28e9": "CobaltStrike/stage",
    # Metasploit
    "5d65ea3fb1d4aa7d826733d2f2cbbb1d": "Metasploit/Meterpreter",
    "c12f54a3f91dc7bafd92b15181b3af14": "Metasploit/reverse_https",
    # Empire
    "2c535aa851f4bc92e8a5b4f6bc5abfe5": "Empire/stager",
    # Trickbot
    "6734f37431670b3ab4292b8f60f29984": "Trickbot",
    "e7d705a3286e19ea42f587b344ee6865": "Trickbot",
    # Emotet
    "4d7a28d6f2263ed61de88ca66eb011e3": "Emotet",
    # Dridex
    "74927e242d6c3a131a35bef3e067afa2": "Dridex",
    # AsyncRAT
    "fc54e0d16d9764783542f0146a98b300": "AsyncRAT",
    # Generic suspicious
    "e35df3e00ca4ef31d42b34bebaa2f86e": "SuspiciousTLS",
    "6fa3244afc6bb6f9fad207b6b52af26b": "PoshC2",
    "1a20c66a14e3c62e37f8290135bca98c": "BruteRatel",
    "cd08e31494f9531f0ab1fd3e8c93b5ca": "Sliver",
}

# ── Known legitimate JA3 hashes (whitelist) ─────────────
KNOWN_GOOD_JA3 = {
    "2a75de52d100f9478c8b5f4dc2f6613c": "Chrome/120+",
    "bd0bf25947d4a37404f0424edf4db9ad": "Firefox/120+",
    "cd08e31494f9531f0ab1fd3e8c93b5ca": "curl",
    "eb1d94daa7e0344597e756a1fb6e7054": "Python/requests",
    "aa79c8e5f48fccd3920b5b45bad9dc0e": "wget",
}


def _md5(s: str) -> str:
    """Calculate MD5 hash of string."""
    return hashlib.md5(s.encode()).hexdigest()


def _parse_uint16(data: bytes, offset: int) -> tuple[int, int]:
    """Parse uint16 big-endian from data at offset."""
    val = struct.unpack("!H", data[offset:offset + 2])[0]
    return val, offset + 2


def _parse_uint8(data: bytes, offset: int) -> tuple[int, int]:
    """Parse uint8 from data at offset."""
    return data[offset], offset + 1


class TLSFingerprint:
    """JA3/JA3S TLS fingerprint generator and analyzer."""

    def __init__(self, push_event_fn=None):
        self.push_event = push_event_fn
        self._lock = Lock()
        self._fingerprints = defaultdict(list)  # JA3 -> [events]
        self._malicious_hits = []
        self._stop = Event()

        TLS_DATA_DIR.mkdir(parents=True, exist_ok=True)

    def compute_ja3(self, client_hello: bytes) -> dict | None:
        """
        Compute JA3 hash from TLS ClientHello raw bytes.

        JA3 format: TLSVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
        """
        try:
            if len(client_hello) < 42:
                return None

            offset = 0

            # TLS record header (5 bytes)
            content_type = client_hello[0]
            if content_type != 22:  # Handshake
                return None
            offset += 5

            # Handshake header
            handshake_type = client_hello[offset]
            if handshake_type != 1:  # ClientHello
                return None
            offset += 4  # type(1) + length(3)

            # Client version
            tls_version, offset = _parse_uint16(client_hello, offset)

            # Random (32 bytes)
            offset += 32

            # Session ID
            session_id_len = client_hello[offset]
            offset += 1 + session_id_len

            # Cipher suites
            cipher_len, offset = _parse_uint16(client_hello, offset)
            ciphers = []
            end = offset + cipher_len
            while offset < end:
                cipher, offset = _parse_uint16(client_hello, offset)
                # Exclude GREASE values
                if (cipher & 0x0f0f) != 0x0a0a:
                    ciphers.append(str(cipher))

            # Compression methods
            comp_len = client_hello[offset]
            offset += 1 + comp_len

            # Extensions
            extensions = []
            elliptic_curves = []
            ec_point_formats = []

            if offset < len(client_hello):
                ext_total_len, offset = _parse_uint16(client_hello, offset)
                ext_end = offset + ext_total_len

                while offset < ext_end and offset < len(client_hello) - 4:
                    ext_type, offset = _parse_uint16(client_hello, offset)
                    ext_len, offset = _parse_uint16(client_hello, offset)

                    # Skip GREASE
                    if (ext_type & 0x0f0f) != 0x0a0a:
                        extensions.append(str(ext_type))

                    ext_data = client_hello[offset:offset + ext_len]

                    # Supported Groups (elliptic curves)
                    if ext_type == 10 and len(ext_data) >= 2:
                        groups_len = struct.unpack("!H", ext_data[:2])[0]
                        for i in range(2, min(2 + groups_len, len(ext_data)), 2):
                            group = struct.unpack(
                                "!H", ext_data[i:i + 2])[0]
                            if (group & 0x0f0f) != 0x0a0a:
                                elliptic_curves.append(str(group))

                    # EC Point Formats
                    if ext_type == 11 and len(ext_data) >= 1:
                        fmt_len = ext_data[0]
                        for i in range(1, min(1 + fmt_len, len(ext_data))):
                            ec_point_formats.append(str(ext_data[i]))

                    offset += ext_len

            # Build JA3 string
            ja3_str = ",".join([
                str(tls_version),
                "-".join(ciphers),
                "-".join(extensions),
                "-".join(elliptic_curves),
                "-".join(ec_point_formats),
            ])

            ja3_hash = _md5(ja3_str)

            return {
                "ja3": ja3_hash,
                "ja3_full": ja3_str,
                "tls_version": tls_version,
                "cipher_count": len(ciphers),
                "extension_count": len(extensions),
            }

        except (IndexError, struct.error) as e:
            logging.debug(f"JA3 parse error: {e}")
            return None

    def analyze_ja3(self, ja3_hash: str, src_ip: str = "",
                    dst_ip: str = "", dst_port: int = 0,
                    pid: int = 0, comm: str = "") -> dict | None:
        """Check JA3 hash against known databases."""
        # Check malicious
        if ja3_hash in KNOWN_MALICIOUS_JA3:
            malware = KNOWN_MALICIOUS_JA3[ja3_hash]
            result = {
                "action": "ALERT",
                "reason": "MALICIOUS_JA3",
                "mitre_id": "T1071.001",
                "detail": f"악성 TLS 핑거프린트: {malware} "
                         f"(JA3={ja3_hash[:16]}... "
                         f"pid={pid} {comm} → {dst_ip}:{dst_port})",
                "alert_level": 3,
                "ja3": ja3_hash,
                "malware": malware,
                "pid": pid,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "source": "TLS",
            }
            with self._lock:
                self._malicious_hits.append({
                    **result, "time": datetime.now().isoformat()
                })
            if self.push_event:
                self.push_event(result)
            return result

        # Track fingerprint
        with self._lock:
            self._fingerprints[ja3_hash].append({
                "time": datetime.now().isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "pid": pid,
                "comm": comm,
                "known": ja3_hash in KNOWN_GOOD_JA3,
            })

        return None

    def process_packet(self, packet_data: bytes, src_ip: str = "",
                       dst_ip: str = "", dst_port: int = 0,
                       pid: int = 0, comm: str = "") -> dict | None:
        """Process raw TLS packet and check fingerprint."""
        ja3 = self.compute_ja3(packet_data)
        if not ja3:
            return None

        return self.analyze_ja3(ja3["ja3"], src_ip, dst_ip, dst_port,
                               pid, comm)

    # ── API helpers ──────────────────────────────────────

    def get_fingerprints(self) -> dict:
        with self._lock:
            unique = len(self._fingerprints)
            total = sum(len(v) for v in self._fingerprints.values())
            malicious = len(self._malicious_hits)

            top = sorted(self._fingerprints.items(),
                        key=lambda x: len(x[1]), reverse=True)[:20]

            return {
                "unique_fingerprints": unique,
                "total_connections": total,
                "malicious_hits": malicious,
                "top_fingerprints": [
                    {
                        "ja3": ja3,
                        "count": len(events),
                        "known": KNOWN_GOOD_JA3.get(ja3, ""),
                        "malicious": KNOWN_MALICIOUS_JA3.get(ja3, ""),
                        "last_seen": events[-1]["time"] if events else "",
                    }
                    for ja3, events in top
                ],
                "recent_malicious": self._malicious_hits[-20:],
            }

    def get_malicious_ja3_list(self) -> dict:
        """Return known malicious JA3 database."""
        return {
            "count": len(KNOWN_MALICIOUS_JA3),
            "hashes": {k: v for k, v in KNOWN_MALICIOUS_JA3.items()},
        }
