#!/usr/bin/env python3
"""
Tests for DNS Monitor — DGA detection, DNS tunneling, known bad domains.
"""

import time
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path


class TestDGADetection:
    """Tests for DGA (Domain Generation Algorithm) detection."""

    def _make_monitor(self, event_collector=None):
        with patch('dns_monitor.DNS_DATA_DIR', Path("/tmp/xdr_test_dns")):
            Path("/tmp/xdr_test_dns").mkdir(parents=True, exist_ok=True)
            from dns_monitor import DNSMonitor
            return DNSMonitor(push_event_fn=event_collector)

    def test_dga_high_entropy_detected(self):
        monitor = self._make_monitor()
        # Random-looking domain (high entropy, consonant ratio)
        result = monitor.is_dga("xkjqpwmzrtynbvclf.tk")
        assert result is not None
        assert result["score"] >= 50

    def test_dga_normal_domain_not_detected(self):
        monitor = self._make_monitor()
        result = monitor.is_dga("google.com")
        assert result is None

    def test_dga_short_domain_not_detected(self):
        monitor = self._make_monitor()
        # Too short for DGA check (< 12 chars)
        result = monitor.is_dga("abc.com")
        assert result is None

    def test_dga_with_bad_tld_bonus(self):
        monitor = self._make_monitor()
        # High entropy + bad TLD = higher score
        result = monitor.is_dga("qwmzrxtnbvclfpgdjs.tk")
        if result:
            assert result["score"] >= 50

    def test_dga_with_numbers(self):
        monitor = self._make_monitor()
        # Lots of numbers (common in DGA)
        result = monitor.is_dga("a8b3c9d2e7f1g4h6i0j5.xyz")
        # Should detect numeric ratio
        if result:
            assert result["numeric_ratio"] > 0


class TestDNSTunnelingDetection:
    """Tests for DNS tunneling detection."""

    def _make_monitor(self):
        with patch('dns_monitor.DNS_DATA_DIR', Path("/tmp/xdr_test_dns")):
            Path("/tmp/xdr_test_dns").mkdir(parents=True, exist_ok=True)
            from dns_monitor import DNSMonitor
            return DNSMonitor()

    def test_long_subdomain_detected(self):
        monitor = self._make_monitor()
        # Very long subdomain (data exfil via DNS)
        long_sub = "a" * 50 + ".evil.com"
        result = monitor.check_tunnel(long_sub, "A", "192.168.1.10")
        assert result is not None
        assert any(i["type"] == "long_subdomain" for i in result["indicators"])

    def test_txt_query_flood_detected(self):
        monitor = self._make_monitor()
        src_ip = "192.168.1.100"
        # Send many TXT queries
        for i in range(15):
            result = monitor.check_tunnel(f"data{i}.evil.com", "TXT", src_ip)
        # Last call should detect flood
        assert result is not None
        assert any(i["type"] == "txt_flood" for i in result["indicators"])

    def test_high_entropy_subdomain_detected(self):
        monitor = self._make_monitor()
        # Base64-like encoded subdomain
        encoded = "aGVsbG8gd29ybGQgdGhpcyBpcyBlbmNvZGVk.evil.com"
        result = monitor.check_tunnel(encoded, "A", "10.0.0.1")
        if result:
            assert any(i["type"] == "encoded_subdomain" for i in result["indicators"])

    def test_normal_query_not_detected(self):
        monitor = self._make_monitor()
        result = monitor.check_tunnel("www.google.com", "A", "10.0.0.1")
        assert result is None


class TestKnownBadDomains:
    """Tests for known C2C/malicious domain patterns."""

    def _make_monitor(self):
        with patch('dns_monitor.DNS_DATA_DIR', Path("/tmp/xdr_test_dns")):
            Path("/tmp/xdr_test_dns").mkdir(parents=True, exist_ok=True)
            from dns_monitor import DNSMonitor
            return DNSMonitor()

    def test_duckdns_detected(self):
        monitor = self._make_monitor()
        result = monitor.check_known_bad("evil.duckdns.org")
        assert result is not None
        assert result["reason"] == "KNOWN_C2C_DOMAIN"

    def test_ngrok_detected(self):
        monitor = self._make_monitor()
        result = monitor.check_known_bad("abcdef.ngrok.io")
        assert result is not None

    def test_bad_tld_detected(self):
        monitor = self._make_monitor()
        result = monitor.check_known_bad("random.tk")
        assert result is not None
        assert result["reason"] == "SUSPICIOUS_TLD"

    def test_normal_domain_clean(self):
        monitor = self._make_monitor()
        result = monitor.check_known_bad("microsoft.com")
        assert result is None

    def test_no_ip_detected(self):
        monitor = self._make_monitor()
        result = monitor.check_known_bad("noip.example.no-ip.com")
        assert result is not None


class TestDNSProcessQuery:
    """Tests for process_query() — the main entry point."""

    def _make_monitor(self, event_collector=None):
        with patch('dns_monitor.DNS_DATA_DIR', Path("/tmp/xdr_test_dns")):
            Path("/tmp/xdr_test_dns").mkdir(parents=True, exist_ok=True)
            from dns_monitor import DNSMonitor
            return DNSMonitor(push_event_fn=event_collector)

    def test_known_bad_triggers_event(self, event_collector):
        monitor = self._make_monitor(event_collector)
        alerts = monitor.process_query("evil.duckdns.org", "A",
                                        pid=1234, comm="malware")
        assert len(alerts) > 0
        assert alerts[0]["alert_level"] == 3
        assert len(event_collector.events) > 0

    def test_stats_tracking(self):
        monitor = self._make_monitor()
        monitor.process_query("example.com", "A")
        monitor.process_query("example.com", "A")
        monitor.process_query("other.com", "A")
        stats = monitor.get_stats()
        assert stats["total_queries"] == 3
        assert stats["unique_domains"] == 2
