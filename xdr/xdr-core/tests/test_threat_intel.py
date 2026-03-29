#!/usr/bin/env python3
"""
Tests for Threat Intelligence Feed — IOC matching, feed parsing, cache.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestThreatIntelMatching:
    """Tests for IOC matching (IP, domain, SHA256, JA3)."""

    def _make_feed(self, event_collector=None):
        with patch('threat_intel.TI_DATA_DIR', Path("/tmp/xdr_test_ti")):
            with patch('threat_intel.TI_CACHE_FILE', Path("/tmp/xdr_test_ti/cache.json")):
                Path("/tmp/xdr_test_ti").mkdir(parents=True, exist_ok=True)
                from threat_intel import ThreatIntelFeed
                feed = ThreatIntelFeed(push_event_fn=event_collector)
                return feed

    def test_check_ip_match(self):
        feed = self._make_feed()
        feed._malicious_ips.add("10.0.0.1")
        result = feed.check_ip("10.0.0.1")
        assert result is not None
        assert result["reason"] == "TI_MALICIOUS_IP"
        assert result["alert_level"] == 3
        assert result["mitre_id"] == "T1071"

    def test_check_ip_no_match(self):
        feed = self._make_feed()
        result = feed.check_ip("192.168.1.1")
        assert result is None

    def test_check_domain_match(self):
        feed = self._make_feed()
        feed._malicious_domains.add("evil.example.com")
        result = feed.check_domain("evil.example.com")
        assert result is not None
        assert result["reason"] == "TI_MALICIOUS_DOMAIN"

    def test_check_domain_no_match(self):
        feed = self._make_feed()
        result = feed.check_domain("google.com")
        assert result is None

    def test_check_sha256_match(self):
        feed = self._make_feed()
        test_hash = "a1b2c3d4" * 8  # 64 chars
        feed._malicious_sha256.add(test_hash)
        result = feed.check_sha256(test_hash)
        assert result is not None
        assert result["reason"] == "TI_MALICIOUS_HASH"

    def test_check_sha256_case_insensitive(self):
        feed = self._make_feed()
        test_hash = "a1b2c3d4" * 8
        feed._malicious_sha256.add(test_hash)
        result = feed.check_sha256(test_hash.upper())
        assert result is not None

    def test_check_ja3_match(self):
        feed = self._make_feed()
        ja3_hash = "e7d705a3286e19ea42f587b344ee6865"
        feed._malicious_ja3[ja3_hash] = "Emotet"
        result = feed.check_ja3(ja3_hash)
        assert result is not None
        assert result["malware"] == "Emotet"
        assert result["reason"] == "TI_MALICIOUS_JA3"

    def test_check_ja3_no_match(self):
        feed = self._make_feed()
        result = feed.check_ja3("0" * 32)
        assert result is None


class TestThreatIntelParsing:
    """Tests for feed parsing functions."""

    def _make_feed(self):
        with patch('threat_intel.TI_DATA_DIR', Path("/tmp/xdr_test_ti")):
            with patch('threat_intel.TI_CACHE_FILE', Path("/tmp/xdr_test_ti/cache.json")):
                Path("/tmp/xdr_test_ti").mkdir(parents=True, exist_ok=True)
                from threat_intel import ThreatIntelFeed
                return ThreatIntelFeed()

    def test_parse_ip_feed(self):
        feed = self._make_feed()
        lines = [
            "# Comment line",
            "10.0.0.1",
            "192.168.1.1",
            "// Another comment",
            "invalid_ip",
            "256.256.256.256",
            "172.16.0.1",
        ]
        ips = feed._parse_ip_feed(lines)
        assert "10.0.0.1" in ips
        assert "192.168.1.1" in ips
        assert "172.16.0.1" in ips
        assert "invalid_ip" not in ips
        assert "256.256.256.256" not in ips

    def test_parse_url_feed(self):
        feed = self._make_feed()
        lines = [
            "# Comment",
            "http://evil.com/malware.exe",
            "https://bad.example.org/payload",
        ]
        urls, domains = feed._parse_url_feed(lines)
        assert "http://evil.com/malware.exe" in urls
        assert "evil.com" in domains
        assert "bad.example.org" in domains

    def test_parse_csv_sha256(self):
        feed = self._make_feed()
        lines = [
            "# Listingdate,SHA256,Listing reason",
            "2024-01-01," + "a" * 64 + ",Malware",
            "2024-01-02," + "b" * 64 + ",Trojan",
            "2024-01-03,invalid_hash,BadHash",
        ]
        hashes = feed._parse_csv_sha256(lines)
        assert "a" * 64 in hashes
        assert "b" * 64 in hashes
        assert "invalid_hash" not in hashes

    def test_parse_csv_ja3(self):
        feed = self._make_feed()
        lines = [
            "# Listingdate,JA3,Malware",
            "2024-01-01," + "c" * 32 + ",Emotet",
            "2024-01-02," + "d" * 32 + ",TrickBot",
        ]
        ja3_map = feed._parse_csv_ja3(lines)
        assert "c" * 32 in ja3_map
        assert ja3_map["c" * 32] == "Emotet"

    def test_is_valid_ip(self):
        feed = self._make_feed()
        assert feed._is_valid_ip("192.168.1.1") is True
        assert feed._is_valid_ip("0.0.0.0") is True
        assert feed._is_valid_ip("255.255.255.255") is True
        assert feed._is_valid_ip("256.0.0.1") is False
        assert feed._is_valid_ip("abc.def.ghi.jkl") is False
        assert feed._is_valid_ip("10.0.0") is False
        assert feed._is_valid_ip("") is False


class TestThreatIntelCache:
    """Tests for IOC cache persistence."""

    def test_save_and_load_cache(self, tmp_path):
        cache_file = tmp_path / "ioc_cache.json"
        with patch('threat_intel.TI_DATA_DIR', tmp_path):
            with patch('threat_intel.TI_CACHE_FILE', cache_file):
                from threat_intel import ThreatIntelFeed
                feed = ThreatIntelFeed()
                feed._malicious_ips = {"1.2.3.4", "5.6.7.8"}
                feed._malicious_domains = {"evil.com"}
                feed._malicious_sha256 = {"a" * 64}
                feed._malicious_ja3 = {"b" * 32: "Malware"}
                feed._save_cache()

                assert cache_file.exists()

                # Create new instance and load
                feed2 = ThreatIntelFeed()
                assert "1.2.3.4" in feed2._malicious_ips
                assert "evil.com" in feed2._malicious_domains

    def test_get_stats(self, tmp_path):
        with patch('threat_intel.TI_DATA_DIR', tmp_path):
            with patch('threat_intel.TI_CACHE_FILE', tmp_path / "cache.json"):
                from threat_intel import ThreatIntelFeed
                feed = ThreatIntelFeed()
                feed._malicious_ips = {"1.2.3.4"}
                feed._total_iocs = 1
                stats = feed.get_stats()
                assert stats["total_iocs"] == 1
                assert stats["malicious_ips"] == 1
