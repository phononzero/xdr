#!/usr/bin/env python3
"""
XDR TLS Fingerprint — JA3/JA3S TLS fingerprinting.

Parses TLS ClientHello from captured packets to generate JA3 hashes.
Compares against known malicious fingerprints database.
"""

import hashlib
import struct
import socket
import logging
import json
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from threading import Thread, Event, Lock

TLS_DATA_DIR = Path("/opt/xdr/tls")

# AF_PACKET constants
_ETH_P_IP = 0x0800
_ETH_HDR_LEN = 14

# Classic BPF filter: accept only IPv4/TCP frames (drop everything else in
# kernel so the Python sniffer only wakes for TCP). Equivalent to tcpdump "tcp".
#   ldh [12]; jeq 0x0800 ->; ldb [23]; jeq 6 -> accept(262144) else drop(0)
_BPF_TCP_ONLY = [
    (0x28, 0, 0, 0x0000000c),
    (0x15, 0, 3, 0x00000800),
    (0x30, 0, 0, 0x00000017),
    (0x15, 0, 1, 0x00000006),
    (0x06, 0, 0, 0x00040000),
    (0x06, 0, 0, 0x00000000),
]

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

    def __init__(self, push_event_fn=None, nic_interface: str = "",
                 alert_system=None):
        self.push_event = push_event_fn
        self.nic_interface = nic_interface
        self.alert_system = alert_system
        self._lock = Lock()
        self._fingerprints = defaultdict(list)  # JA3 -> [events]
        self._malicious_hits = []
        self._stop = Event()
        self._thread = None
        self._sock = None
        self._packets_seen = 0
        self._client_hellos = 0
        self.status = "not_started"

        TLS_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # ── Packet capture (raw AF_PACKET sniffer) ──────────────

    def start(self):
        """Start the TLS ClientHello sniffer in a background thread."""
        self._thread = Thread(target=self._sniff_loop, daemon=True,
                              name="tls-fingerprint")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=3)

    def _open_socket(self):
        """Open a raw AF_PACKET socket with a TCP-only cBPF filter."""
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.htons(_ETH_P_IP))
        # Attach classic BPF so the kernel drops non-TCP before wakeup.
        try:
            import ctypes
            fprog_buf = b"".join(
                struct.pack("HBBI", code, jt, jf, k)
                for (code, jt, jf, k) in _BPF_TCP_ONLY
            )
            buf = ctypes.create_string_buffer(fprog_buf)
            # struct sock_fprog { unsigned short len; struct sock_filter *filter; }
            fprog = struct.pack("HxxxxxxP", len(_BPF_TCP_ONLY),
                                ctypes.addressof(buf))
            SO_ATTACH_FILTER = 26
            s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
            # keep buf alive for the socket's lifetime
            self._filter_buf = buf
        except Exception as e:
            logging.debug(f"TLS: cBPF filter attach failed ({e}); "
                         "falling back to Python-side filtering")
        if self.nic_interface:
            try:
                s.bind((self.nic_interface, 0))
            except OSError as e:
                logging.warning(f"TLS: bind to {self.nic_interface} failed: {e}")
        s.settimeout(1.0)
        return s

    def _sniff_loop(self):
        """Capture TCP frames, extract TLS ClientHello, compute JA3."""
        try:
            self._sock = self._open_socket()
        except PermissionError:
            self.status = "no_permission"
            logging.warning("TLS: raw socket needs root — fingerprinting disabled")
            return
        except OSError as e:
            self.status = "error"
            logging.warning(f"TLS: cannot open raw socket: {e}")
            return

        self.status = "running"
        logging.info("TLS fingerprint: sniffing ClientHello on %s",
                     self.nic_interface or "all interfaces")

        while not self._stop.is_set():
            try:
                frame = self._sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            self._packets_seen += 1
            try:
                self._handle_frame(frame)
            except Exception as e:
                logging.debug(f"TLS frame parse error: {e}")

    def _handle_frame(self, frame: bytes):
        """Parse Ethernet/IP/TCP, detect TLS ClientHello, feed to JA3."""
        if len(frame) < _ETH_HDR_LEN + 20:
            return
        # IPv4 header
        ip_off = _ETH_HDR_LEN
        ver_ihl = frame[ip_off]
        if (ver_ihl >> 4) != 4:
            return
        ihl = (ver_ihl & 0x0f) * 4
        if frame[ip_off + 9] != 6:  # protocol != TCP
            return
        src_ip = socket.inet_ntoa(frame[ip_off + 12:ip_off + 16])
        dst_ip = socket.inet_ntoa(frame[ip_off + 16:ip_off + 20])

        # TCP header
        tcp_off = ip_off + ihl
        if len(frame) < tcp_off + 20:
            return
        dst_port = struct.unpack("!H", frame[tcp_off + 2:tcp_off + 4])[0]
        data_off = (frame[tcp_off + 12] >> 4) * 4
        payload = frame[tcp_off + data_off:]

        # TLS handshake record: content_type=22(0x16), version 0x03xx
        if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
            return
        if payload[5] != 0x01:  # not a ClientHello
            return

        self._client_hellos += 1
        result = self.process_packet(payload, src_ip=src_ip, dst_ip=dst_ip,
                                     dst_port=dst_port)
        if result and result.get("reason") == "MALICIOUS_JA3" and self.alert_system:
            self.alert_system.send(result.get("alert_level", 3),
                                   "MALICIOUS_JA3", result.get("detail", ""))

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
                "status": self.status,
                "packets_seen": self._packets_seen,
                "client_hellos": self._client_hellos,
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
