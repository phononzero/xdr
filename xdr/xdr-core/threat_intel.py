#!/usr/bin/env python3
"""
XDR Threat Intelligence Feed — IOC auto-update from public sources.

Sources:
  - Abuse.ch URLhaus (malicious URLs/IPs)
  - Abuse.ch Feodo Tracker (C2C IPs — Emotet, Dridex, TrickBot)
  - Abuse.ch SSL Blacklist (malicious SHA256/JA3)
  - Emerging Threats compromised IPs

MITRE ATT&CK: T1588.002 (Obtain Capabilities: Tool)
"""

import os
import csv
import json
import logging
import hashlib
import time
import io
from datetime import datetime, timedelta
from pathlib import Path
from threading import Thread, Event, Lock
from urllib.request import urlopen, Request
from urllib.error import URLError

logger = logging.getLogger("xdr.threat_intel")

TI_DATA_DIR = Path("/opt/xdr/threat_intel")
TI_CACHE_FILE = TI_DATA_DIR / "ioc_cache.json"

# ── Public IOC Feed URLs ─────────────────────────────────
FEEDS = {
    "feodo_ip": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        "type": "ip",
        "description": "Feodo Tracker — C2C IPs (Emotet, Dridex, TrickBot, QakBot)",
        "interval": 3600,  # 1 hour
    },
    "urlhaus_domain": {
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "type": "url",
        "description": "URLhaus — Active malicious URLs",
        "interval": 3600,
    },
    "sslbl_sha256": {
        "url": "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        "type": "sha256",
        "description": "SSL Blacklist — Malicious certificate SHA256",
        "interval": 7200,  # 2 hours
    },
    "sslbl_ja3": {
        "url": "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
        "type": "ja3",
        "description": "SSL Blacklist — Malicious JA3 fingerprints",
        "interval": 7200,
    },
    "et_compromised": {
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip",
        "description": "Emerging Threats — Compromised IPs",
        "interval": 7200,
    },
}

# HTTP request timeout
_TIMEOUT = 15
_USER_AGENT = "XDR-ThreatIntel/1.0"


class ThreatIntelFeed:
    """Threat intelligence feed aggregator and IOC matcher."""

    def __init__(self, push_event_fn=None, blocklist_store=None):
        self.push_event = push_event_fn
        self.blocklist = blocklist_store
        self._stop = Event()
        self._thread = None
        self._lock = Lock()

        # IOC databases
        self._malicious_ips = set()
        self._malicious_urls = set()
        self._malicious_domains = set()
        self._malicious_sha256 = set()
        self._malicious_ja3 = {}  # hash -> malware name

        # Stats
        self._last_update = {}
        self._feed_stats = {}
        self._total_iocs = 0

        TI_DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Load cached IOCs
        self._load_cache()

    # ── Feed fetching ────────────────────────────────────

    def _fetch_feed(self, name: str, feed: dict) -> list[str]:
        """Fetch a single feed and return raw lines."""
        try:
            req = Request(feed["url"], headers={"User-Agent": _USER_AGENT})
            with urlopen(req, timeout=_TIMEOUT) as resp:
                data = resp.read().decode("utf-8", errors="ignore")
                lines = data.strip().splitlines()
                logger.info(f"TI feed '{name}': fetched {len(lines)} lines")
                return lines
        except (URLError, OSError, TimeoutError) as e:
            logger.warning(f"TI feed '{name}' fetch failed: {e}")
            return []

    def _parse_ip_feed(self, lines: list[str]) -> set[str]:
        """Parse IP address feed (one IP per line, skip comments)."""
        ips = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            # Extract IP (first token)
            ip = line.split()[0].split(",")[0].strip()
            if self._is_valid_ip(ip):
                ips.add(ip)
        return ips

    def _parse_url_feed(self, lines: list[str]) -> tuple[set[str], set[str]]:
        """Parse URL feed, extract domains and full URLs."""
        urls = set()
        domains = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls.add(line)
            # Extract domain from URL
            try:
                if "://" in line:
                    domain = line.split("://", 1)[1].split("/")[0].split(":")[0]
                    domains.add(domain)
            except (IndexError, ValueError):
                pass
        return urls, domains

    def _parse_csv_sha256(self, lines: list[str]) -> set[str]:
        """Parse abuse.ch SSL blacklist CSV for SHA256 hashes."""
        hashes = set()
        reader = csv.reader(io.StringIO("\n".join(lines)))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            # Format: listing_date,sha256,reason
            if len(row) >= 2:
                sha = row[1].strip()
                if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha.lower()):
                    hashes.add(sha.lower())
        return hashes

    def _parse_csv_ja3(self, lines: list[str]) -> dict[str, str]:
        """Parse abuse.ch JA3 blacklist CSV."""
        ja3_map = {}
        reader = csv.reader(io.StringIO("\n".join(lines)))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            # Format: listing_date,ja3_md5,malware
            if len(row) >= 3:
                ja3_hash = row[1].strip()
                malware = row[2].strip()
                if len(ja3_hash) == 32:
                    ja3_map[ja3_hash] = malware
        return ja3_map

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IPv4 or IPv6 address."""
        import socket
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(family, ip.strip())
                return True
            except (OSError, ValueError):
                continue
        return False

    # ── Update cycle ─────────────────────────────────────

    def update_feeds(self):
        """Fetch and update all IOC feeds."""
        now = time.time()
        updated = False

        for name, feed in FEEDS.items():
            # Check if update needed
            last = self._last_update.get(name, 0)
            if now - last < feed["interval"]:
                continue

            lines = self._fetch_feed(name, feed)
            if not lines:
                continue

            count = 0
            if feed["type"] == "ip":
                ips = self._parse_ip_feed(lines)
                with self._lock:
                    self._malicious_ips |= ips
                count = len(ips)

            elif feed["type"] == "url":
                urls, domains = self._parse_url_feed(lines)
                with self._lock:
                    self._malicious_urls |= urls
                    self._malicious_domains |= domains
                count = len(urls)

            elif feed["type"] == "sha256":
                hashes = self._parse_csv_sha256(lines)
                with self._lock:
                    self._malicious_sha256 |= hashes
                count = len(hashes)

            elif feed["type"] == "ja3":
                ja3_map = self._parse_csv_ja3(lines)
                with self._lock:
                    self._malicious_ja3.update(ja3_map)
                count = len(ja3_map)

            self._last_update[name] = now
            self._feed_stats[name] = {
                "last_update": datetime.now().isoformat(),
                "ioc_count": count,
                "description": feed["description"],
            }
            updated = True
            logger.info(f"TI feed '{name}': {count} IOCs loaded")

        if updated:
            with self._lock:
                self._total_iocs = (
                    len(self._malicious_ips) +
                    len(self._malicious_domains) +
                    len(self._malicious_sha256) +
                    len(self._malicious_ja3)
                )
            self._save_cache()

            # Push update event
            if self.push_event:
                self.push_event({
                    "source": "SYSTEM",
                    "action": "TI_UPDATE",
                    "alert_level": 0,
                    "message": f"위협 인텔리전스 업데이트: "
                              f"IP={len(self._malicious_ips)} "
                              f"도메인={len(self._malicious_domains)} "
                              f"SHA256={len(self._malicious_sha256)} "
                              f"JA3={len(self._malicious_ja3)}",
                })

    # ── IOC matching ─────────────────────────────────────

    def check_ip(self, ip: str) -> dict | None:
        """Check if IP is in threat intel feeds."""
        with self._lock:
            if ip in self._malicious_ips:
                return {
                    "source": "DETECTOR",
                    "reason": "TI_MALICIOUS_IP",
                    "mitre_id": "T1071",
                    "alert_level": 3,
                    "detail": f"위협 인텔리전스: 악성 IP 연결 감지 — {ip}",
                    "ioc_type": "ip",
                    "ioc_value": ip,
                }
        return None

    def check_domain(self, domain: str) -> dict | None:
        """Check if domain is in threat intel feeds."""
        with self._lock:
            if domain in self._malicious_domains:
                return {
                    "source": "DETECTOR",
                    "reason": "TI_MALICIOUS_DOMAIN",
                    "mitre_id": "T1071.004",
                    "alert_level": 3,
                    "detail": f"위협 인텔리전스: 악성 도메인 — {domain}",
                    "ioc_type": "domain",
                    "ioc_value": domain,
                }
        return None

    def check_sha256(self, sha256: str) -> dict | None:
        """Check if SHA256 hash is in threat intel feeds."""
        with self._lock:
            if sha256.lower() in self._malicious_sha256:
                return {
                    "source": "DETECTOR",
                    "reason": "TI_MALICIOUS_HASH",
                    "mitre_id": "T1588.002",
                    "alert_level": 3,
                    "detail": f"위협 인텔리전스: 악성 해시 — {sha256[:16]}...",
                    "ioc_type": "sha256",
                    "ioc_value": sha256,
                }
        return None

    def check_ja3(self, ja3_hash: str) -> dict | None:
        """Check if JA3 hash is in threat intel feeds."""
        with self._lock:
            if ja3_hash in self._malicious_ja3:
                malware = self._malicious_ja3[ja3_hash]
                return {
                    "source": "DETECTOR",
                    "reason": "TI_MALICIOUS_JA3",
                    "mitre_id": "T1071.001",
                    "alert_level": 3,
                    "detail": f"위협 인텔리전스: 악성 JA3 — {malware} ({ja3_hash[:16]}...)",
                    "ioc_type": "ja3",
                    "ioc_value": ja3_hash,
                    "malware": malware,
                }
        return None

    # ── Cache persistence ────────────────────────────────

    def _save_cache(self):
        """Save IOC cache to disk."""
        try:
            with self._lock:
                cache = {
                    "updated": datetime.now().isoformat(),
                    "ips": list(self._malicious_ips)[:50000],
                    "domains": list(self._malicious_domains)[:50000],
                    "sha256": list(self._malicious_sha256)[:50000],
                    "ja3": dict(list(self._malicious_ja3.items())[:5000]),
                    "stats": self._feed_stats,
                }
            with open(TI_CACHE_FILE, "w") as f:
                json.dump(cache, f, indent=2, default=str)
            logger.info(f"TI cache saved: {self._total_iocs} IOCs")
        except Exception as e:
            logger.warning(f"TI cache save error: {e}")

    def _load_cache(self):
        """Load IOC cache from disk."""
        try:
            if TI_CACHE_FILE.exists():
                with open(TI_CACHE_FILE) as f:
                    cache = json.load(f)
                with self._lock:
                    self._malicious_ips = set(cache.get("ips", []))
                    self._malicious_domains = set(cache.get("domains", []))
                    self._malicious_sha256 = set(cache.get("sha256", []))
                    self._malicious_ja3 = cache.get("ja3", {})
                    self._feed_stats = cache.get("stats", {})
                    self._total_iocs = (
                        len(self._malicious_ips) +
                        len(self._malicious_domains) +
                        len(self._malicious_sha256) +
                        len(self._malicious_ja3)
                    )
                logger.info(f"TI cache loaded: {self._total_iocs} IOCs")
        except Exception as e:
            logger.warning(f"TI cache load error: {e}")

    # ── Background thread ────────────────────────────────

    def start(self):
        """Start background feed update thread."""
        self._thread = Thread(target=self._update_loop, daemon=True,
                            name="threat-intel")
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _update_loop(self):
        """Periodically update IOC feeds."""
        logger.info("Threat intel feed started")
        # Initial delay
        self._stop.wait(10)

        while not self._stop.is_set():
            try:
                self.update_feeds()
            except Exception as e:
                logger.warning(f"TI update error: {e}")
            self._stop.wait(300)  # Check every 5 minutes

    # ── API helpers ──────────────────────────────────────

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_iocs": self._total_iocs,
                "malicious_ips": len(self._malicious_ips),
                "malicious_domains": len(self._malicious_domains),
                "malicious_sha256": len(self._malicious_sha256),
                "malicious_ja3": len(self._malicious_ja3),
                "feeds": self._feed_stats,
            }
