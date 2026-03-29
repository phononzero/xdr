#!/usr/bin/env python3
"""
Tests for Correlation Engine — APT kill chain scenarios, beacon detection.
"""

import time
import pytest
from unittest.mock import MagicMock


class TestCorrelationEngine:
    """Tests for CorrelationEngine cross-event correlation."""

    def _make_engine(self, mock_log_manager, mock_alert_system, event_collector):
        from engine.correlation import CorrelationEngine
        return CorrelationEngine(mock_log_manager, mock_alert_system,
                                  push_event_fn=event_collector)

    def test_exec_event_logged(self, mock_log_manager, mock_alert_system, event_collector):
        engine = self._make_engine(mock_log_manager, mock_alert_system, event_collector)
        event = {
            "pid": 100, "event_type": 1, "alert_level": 1,
            "comm": "ls", "uid": 1000, "dst_ip": 0, "dst_port": 0,
        }
        engine.process_edr_event(event)
        assert len(event_collector.events) > 0
        assert event_collector.events[0]["source"] == "EDR"

    def test_warning_event_triggers_alert(self, mock_log_manager, mock_alert_system, event_collector):
        engine = self._make_engine(mock_log_manager, mock_alert_system, event_collector)
        event = {
            "pid": 200, "event_type": 1, "alert_level": 2,
            "comm": "suspicious", "uid": 0, "dst_ip": 0, "dst_port": 0,
        }
        engine.process_edr_event(event)
        assert len(mock_log_manager.critical) > 0
        assert len(mock_alert_system.sent) > 0

    def test_c2c_correlation_exec_plus_connect(self, mock_log_manager, mock_alert_system, event_collector):
        """Exec + network connect within 60s window → C2C warning."""
        engine = self._make_engine(mock_log_manager, mock_alert_system, event_collector)

        # Exec event
        engine.process_edr_event({
            "pid": 300, "event_type": 1, "alert_level": 1,
            "comm": "dropper", "uid": 1000, "dst_ip": 0, "dst_port": 0,
        })
        # Connect event same PID
        engine.process_edr_event({
            "pid": 300, "event_type": 3, "alert_level": 1,
            "comm": "dropper", "uid": 1000,
            "dst_ip": 0x0A000001, "dst_port": 4444,
        })

        # Should find CORRELATION event
        correlation_events = [
            e for e in event_collector.events
            if e.get("source") == "CORRELATION"
        ]
        assert len(correlation_events) > 0

    def test_beacon_detection(self, mock_log_manager, mock_alert_system, event_collector):
        """Repeated connections to same IP → beacon detection."""
        engine = self._make_engine(mock_log_manager, mock_alert_system, event_collector)

        # Send 11 connect events to same IP
        for i in range(11):
            engine.process_edr_event({
                "pid": 400 + i, "event_type": 3, "alert_level": 1,
                "comm": "beacon", "uid": 1000,
                "dst_ip": 0xC0A80101, "dst_port": 443,
            })

        beacon_events = [
            e for e in event_collector.events
            if e.get("event_type") == "beacon"
        ]
        assert len(beacon_events) > 0

    def test_ndr_event_logged(self, mock_log_manager, mock_alert_system, event_collector):
        engine = self._make_engine(mock_log_manager, mock_alert_system, event_collector)
        event = {
            "src_ip": 0x0A000001, "dst_ip": 0x0A000002,
            "src_port": 12345, "dst_port": 80,
            "protocol": 6, "alert_level": 1,
            "action": 0, "event_type": 0, "pkt_len": 100,
        }
        engine.process_ndr_event(event)
        ndr_events = [e for e in event_collector.events if e.get("source") == "NDR"]
        assert len(ndr_events) > 0

    def test_cleanup_old_events(self, mock_log_manager, mock_alert_system, event_collector):
        engine = self._make_engine(mock_log_manager, mock_alert_system, event_collector)
        # Add old event
        engine.edr_events[999].append({
            "time": time.time() - 300, "type": 1,
        })
        engine._cleanup_old_events()
        assert 999 not in engine.edr_events

    def test_apt_privesc_c2_scenario(self, mock_log_manager, mock_alert_system, event_collector):
        """APT kill chain: privilege escalation + outbound connection."""
        engine = self._make_engine(mock_log_manager, mock_alert_system, event_collector)

        # Privilege escalation event
        engine.process_edr_event({
            "pid": 500, "event_type": 5, "alert_level": 2,
            "comm": "exploit", "uid": 1000, "dst_ip": 0, "dst_port": 0,
            "reason": "PRIV_ESCALATION", "mitre_id": "T1548",
        })
        # Outbound connection
        engine.process_edr_event({
            "pid": 501, "event_type": 3, "alert_level": 1,
            "comm": "shell", "uid": 0,
            "dst_ip": 0xC0A80101, "dst_port": 4444,
        })

        apt_events = [
            e for e in event_collector.events
            if e.get("event_type") == "apt_kill_chain"
        ]
        assert len(apt_events) > 0
