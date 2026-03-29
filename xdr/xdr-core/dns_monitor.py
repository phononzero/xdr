#!/usr/bin/env python3
"""
XDR DNS Monitor — DNS query surveillance + DGA detection + DNS tunneling detection.

Monitors DNS queries by reading /var/log/syslog (dnsmasq) or tailing
/proc/net/udp for port 53 traffic, plus optional eBPF kprobe on udp_sendmsg.
"""

import os
import re
import math
import time
import json
import logging
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from threading import Thread, Event, Lock

DNS_DATA_DIR = Path("/opt/xdr/dns")
SUSPICIOUS_FILE = DNS_DATA_DIR / "suspicious.json"
STATS_FILE = DNS_DATA_DIR / "stats.json"

# ── Known malicious/C2C TLDs and domains ────────────────

KNOWN_BAD_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Free TLDs (malware favorite)
    ".xyz", ".top", ".buzz", ".club",     # Cheap TLDs (phishing)
    ".onion",                             # Tor
}

KNOWN_C2C_PATTERNS = [
    r"\.duckdns\.org$",
    r"\.no-ip\.(com|org|biz)$",
    r"\.ddns\.net$",
    r"\.dynu\.com$",
    r"\.serveo\.net$",
    r"\.ngrok\.(io|app)$",
    r"\.portmap\.host$",
    r"\.zapto\.org$",
    r"\.hopto\.org$",
]

# ── DGA Detection Thresholds ────────────────────────────

DGA_ENTROPY_THRESHOLD = 3.8      # Shannon entropy
DGA_CONSONANT_RATIO = 0.7        # Consonant ratio threshold
DGA_MIN_LENGTH = 12              # Minimum domain length for DGA check
DGA_MAX_NUM_RATIO = 0.3          # Maximum numeric character ratio
DNS_TUNNEL_TXT_THRESHOLD = 10    # TXT queries per minute
DNS_TUNNEL_SUBDOMAIN_LEN = 40    # Subdomain length for tunneling


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length)
                for count in freq.values())


def _consonant_ratio(s: str) -> float:
    """Calculate ratio of consonant characters."""
    if not s:
        return 0.0
    vowels = set("aeiouAEIOU")
    alpha = [c for c in s if c.isalpha()]
    if not alpha:
        return 0.0
    consonants = sum(1 for c in alpha if c not in vowels)
    return consonants / len(alpha)


def _numeric_ratio(s: str) -> float:
    """Calculate ratio of numeric characters."""
    if not s:
        return 0.0
    return sum(1 for c in s if c.isdigit()) / len(s)


def _extract_domain_parts(domain: str) -> tuple[str, str, str]:
    """Extract subdomain, domain, and TLD from FQDN."""
    parts = domain.rstrip(".").split(".")
    if len(parts) >= 3:
        tld = f".{parts[-1]}"
        main = parts[-2]
        subdomain = ".".join(parts[:-2])
        return subdomain, main, tld
    elif len(parts) == 2:
        return "", parts[0], f".{parts[1]}"
    return "", domain, ""


class DNSMonitor:
    """DNS query monitor with DGA and tunnel detection."""

    def __init__(self, push_event_fn=None):
        self.push_event = push_event_fn
        self._stop = Event()
        self._thread = None
        self._lock = Lock()

        # Statistics
        self._query_count = 0
        self._suspicious_domains = []
        self._dga_detections = []
        self._tunnel_detections = []
        self._txt_query_log = defaultdict(list)  # IP -> [timestamp]
        self._domain_query_log = defaultdict(int)  # domain -> count

        DNS_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # ── DGA Detection ────────────────────────────────────

    def is_dga(self, domain: str) -> dict | None:
        """Check if domain looks like DGA-generated."""
        subdomain, main_domain, tld = _extract_domain_parts(domain)

        # Check the main domain part
        check_str = main_domain
        if len(check_str) < DGA_MIN_LENGTH:
            return None

        entropy = _shannon_entropy(check_str)
        cons_ratio = _consonant_ratio(check_str)
        num_ratio = _numeric_ratio(check_str)

        # DGA score (0-100)
        score = 0
        if entropy > DGA_ENTROPY_THRESHOLD:
            score += 30
        if cons_ratio > DGA_CONSONANT_RATIO:
            score += 25
        if num_ratio > DGA_MAX_NUM_RATIO:
            score += 20
        if tld in KNOWN_BAD_TLDS:
            score += 15
        if len(check_str) > 20:
            score += 10

        if score >= 50:
            return {
                "domain": domain,
                "score": score,
                "entropy": round(entropy, 2),
                "consonant_ratio": round(cons_ratio, 2),
                "numeric_ratio": round(num_ratio, 2),
                "length": len(check_str),
            }
        return None

    # ── DNS Tunneling Detection ──────────────────────────

    def check_tunnel(self, domain: str, query_type: str,
                     src_ip: str) -> dict | None:
        """Detect DNS tunneling patterns."""
        subdomain, main_domain, tld = _extract_domain_parts(domain)

        alerts = []

        # 1. Long subdomain (data encoding)
        if subdomain and len(subdomain) > DNS_TUNNEL_SUBDOMAIN_LEN:
            alerts.append({
                "type": "long_subdomain",
                "detail": f"비정상 서브도메인 길이: {len(subdomain)}자",
                "subdomain_length": len(subdomain),
            })

        # 2. Excessive TXT queries from same source
        if query_type == "TXT":
            now = time.time()
            self._txt_query_log[src_ip].append(now)
            # Keep last 60 seconds
            self._txt_query_log[src_ip] = [
                t for t in self._txt_query_log[src_ip] if now - t < 60
            ]
            count = len(self._txt_query_log[src_ip])
            if count >= DNS_TUNNEL_TXT_THRESHOLD:
                alerts.append({
                    "type": "txt_flood",
                    "detail": f"TXT 쿼리 폭주: {count}회/60초 from {src_ip}",
                    "count": count,
                })

        # 3. High entropy subdomain (encoded data)
        if subdomain:
            entropy = _shannon_entropy(subdomain.replace(".", ""))
            if entropy > 4.0 and len(subdomain) > 20:
                alerts.append({
                    "type": "encoded_subdomain",
                    "detail": f"인코딩된 서브도메인 (엔트로피={entropy:.2f})",
                    "entropy": round(entropy, 2),
                })

        if alerts:
            return {
                "domain": domain,
                "query_type": query_type,
                "src_ip": src_ip,
                "indicators": alerts,
            }
        return None

    # ── Known bad domain check ───────────────────────────

    def check_known_bad(self, domain: str) -> dict | None:
        """Check against known C2C/malicious patterns."""
        for pattern in KNOWN_C2C_PATTERNS:
            if re.search(pattern, domain, re.IGNORECASE):
                return {
                    "domain": domain,
                    "reason": "KNOWN_C2C_DOMAIN",
                    "pattern": pattern,
                }

        _, _, tld = _extract_domain_parts(domain)
        if tld in KNOWN_BAD_TLDS:
            return {
                "domain": domain,
                "reason": "SUSPICIOUS_TLD",
                "tld": tld,
            }
        return None

    # ── Process DNS event ────────────────────────────────

    def process_query(self, domain: str, query_type: str = "A",
                      src_ip: str = "", pid: int = 0,
                      comm: str = "") -> list[dict]:
        """Process a DNS query and return any alerts."""
        alerts = []
        with self._lock:
            self._query_count += 1
            self._domain_query_log[domain] += 1

        # 1. Known bad domain check
        bad = self.check_known_bad(domain)
        if bad:
            alert = {
                "action": "ALERT",
                "reason": bad["reason"],
                "mitre_id": "T1071.004",
                "detail": f"악성 도메인 쿼리: {domain} "
                         f"(pid={pid} comm={comm})",
                "alert_level": 3,
                "domain": domain,
                "pid": pid,
                "source": "DNS",
            }
            alerts.append(alert)
            if self.push_event:
                self.push_event(alert)

        # 2. DGA detection
        dga = self.is_dga(domain)
        if dga:
            alert = {
                "action": "ALERT",
                "reason": "DGA_DOMAIN",
                "mitre_id": "T1568.002",
                "detail": f"DGA 의심 도메인: {domain} "
                         f"(점수={dga['score']}, 엔트로피={dga['entropy']})",
                "alert_level": 2,
                "domain": domain,
                "dga_score": dga["score"],
                "pid": pid,
                "source": "DNS",
            }
            alerts.append(alert)
            with self._lock:
                self._dga_detections.append({
                    **dga, "time": datetime.now().isoformat(),
                    "pid": pid, "comm": comm,
                })
            if self.push_event:
                self.push_event(alert)

        # 3. DNS tunneling check
        tunnel = self.check_tunnel(domain, query_type, src_ip)
        if tunnel:
            alert = {
                "action": "ALERT",
                "reason": "DNS_TUNNEL",
                "mitre_id": "T1572",
                "detail": f"DNS 터널링 의심: {domain} "
                         f"({', '.join(i['type'] for i in tunnel['indicators'])})",
                "alert_level": 3,
                "domain": domain,
                "indicators": tunnel["indicators"],
                "pid": pid,
                "source": "DNS",
            }
            alerts.append(alert)
            with self._lock:
                self._tunnel_detections.append({
                    **tunnel, "time": datetime.now().isoformat(),
                    "pid": pid, "comm": comm,
                })
            if self.push_event:
                self.push_event(alert)

        return alerts

    # ── API helpers ──────────────────────────────────────

    def get_stats(self) -> dict:
        with self._lock:
            top_domains = sorted(self._domain_query_log.items(),
                               key=lambda x: x[1], reverse=True)[:20]
            return {
                "total_queries": self._query_count,
                "unique_domains": len(self._domain_query_log),
                "dga_detections": len(self._dga_detections),
                "tunnel_detections": len(self._tunnel_detections),
                "top_domains": [{"domain": d, "count": c}
                               for d, c in top_domains],
            }

    def get_suspicious(self) -> list[dict]:
        with self._lock:
            return (self._dga_detections[-50:]
                    + self._tunnel_detections[-50:])

    # ── Background syslog tail ───────────────────────────

    def start(self):
        self._thread = Thread(target=self._tail_syslog, daemon=True,
                            name="dns-monitor")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _tail_syslog(self):
        """Tail syslog/journald for DNS queries."""
        logging.info("DNS monitor started")

        # Try journalctl for dnsmasq/systemd-resolved
        try:
            proc = subprocess.Popen(
                ["journalctl", "-f", "-u", "systemd-resolved",
                 "--no-pager", "-o", "short"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True
            )
            while not self._stop.is_set():
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                self._parse_dns_line(line.strip())
            proc.terminate()
        except Exception:
            # Fallback: poll /proc/net/udp for port 53 activity
            logging.info("DNS monitor: fallback to /proc/net/udp polling")
            while not self._stop.wait(5):
                self._poll_dns_connections()

    def _parse_dns_line(self, line: str):
        """Parse DNS query from syslog line."""
        # systemd-resolved format: "... query[A] example.com ..."
        match = re.search(r"query\[(\w+)\]\s+(\S+)", line)
        if match:
            qtype = match.group(1)
            domain = match.group(2)
            self.process_query(domain, qtype)

        # dnsmasq format: "... query[A] example.com from 192.168.1.100"
        match = re.search(
            r"query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)", line)
        if match:
            qtype = match.group(1)
            domain = match.group(2)
            src_ip = match.group(3)
            self.process_query(domain, qtype, src_ip)

    def _poll_dns_connections(self):
        """Poll /proc/net/udp for port 53 connections."""
        try:
            with open("/proc/net/udp") as f:
                for line in f:
                    if ":0035 " in line:  # port 53 = 0x0035
                        with self._lock:
                            self._query_count += 1
        except OSError:
            pass
