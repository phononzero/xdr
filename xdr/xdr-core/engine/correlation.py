"""
XDR Correlation Engine — Cross-correlates EDR + NDR events.
"""

import time
import logging
from collections import defaultdict
from threading import Lock

from .ebpf_structs import (
    EVT_PROCESS_EXEC, EVT_NET_CONNECT, EVT_NAMES, NDR_EVT_NAMES,
    ALERT_INFO, ALERT_WARNING, ALERT_CRITICAL,
)
from .log_manager import LogManager
from .alert_system import AlertSystem
from .utils import ip_str

# Correlation thresholds — loaded from config
from config_loader import get_config as _get_config
_corr_cfg = _get_config()["correlation"]
CORRELATION_WINDOW_SECS = _corr_cfg["window_secs"]
EXEC_RATE_THRESHOLD = _corr_cfg["exec_rate_threshold"]
CONNECT_RATE_THRESHOLD = _corr_cfg["connect_rate_threshold"]
BEACON_DETECT_COUNT = _corr_cfg["beacon_detect_count"]


class CorrelationEngine:
    """Correlates EDR + NDR events to detect complex threats."""

    def __init__(self, log_manager: LogManager, alert_system: AlertSystem,
                 push_event_fn=None):
        self.log = log_manager
        self.alert = alert_system
        self.push_event = push_event_fn or (lambda e: None)
        self._lock = Lock()
        self.edr_events = defaultdict(list)
        self.ndr_events = defaultdict(list)
        self.connect_counts = defaultdict(int)
        self.exec_count = 0
        self.last_cleanup = time.time()
        self._apt_alerts_seen = set()  # Dedup APT kill chain alerts per cycle

    def process_edr_event(self, event: dict):
        """Handle an EDR event from eBPF ring buffer."""
        pid = event.get("pid", 0)
        evt_type = event.get("event_type", 0)
        alert_level = event.get("alert_level", ALERT_INFO)
        comm = event.get("comm", "unknown")

        evt_name = EVT_NAMES.get(evt_type, f"UNKNOWN({evt_type})")
        msg = (
            f"EDR {evt_name} pid={pid} comm={comm} "
            f"uid={event.get('uid', 0)} "
            f"dst={ip_str(event.get('dst_ip', 0))}:"
            f"{event.get('dst_port', 0)}"
        )

        # Track for correlation
        self.edr_events[pid].append({
            "time": time.time(), "type": evt_type, **event
        })
        if evt_type == EVT_PROCESS_EXEC:
            self.exec_count += 1
        if evt_type == EVT_NET_CONNECT:
            dst_ip = event.get("dst_ip", 0)
            self.connect_counts[dst_ip] += 1

        # Push to dashboard
        event["source"] = "EDR"
        event["comm"] = comm
        event["dst_ip"] = ip_str(event.get("dst_ip", 0))
        self.push_event(event)

        # Log and alert based on level
        if alert_level >= ALERT_WARNING:
            self.log.write_critical(msg)
            self.alert.send(alert_level, evt_name, msg)
        else:
            self.log.write_general(msg)

        # Run correlation checks
        self._check_correlations(pid, event)

    def process_ndr_event(self, event: dict):
        """Handle an NDR event from XDP ring buffer."""
        src_ip = event.get("src_ip", 0)
        dst_ip = event.get("dst_ip", 0)
        evt_type = event.get("event_type", 0)
        alert_level = event.get("alert_level", ALERT_INFO)
        action = "DROP" if event.get("action", 0) else "PASS"

        evt_name = NDR_EVT_NAMES.get(evt_type, f"UNKNOWN({evt_type})")
        msg = (
            f"NDR {evt_name} {ip_str(src_ip)}:{event.get('src_port', 0)} → "
            f"{ip_str(dst_ip)}:{event.get('dst_port', 0)} "
            f"proto={event.get('protocol', 0)} action={action} "
            f"len={event.get('pkt_len', 0)}"
        )

        self.ndr_events[dst_ip].append({
            "time": time.time(), "type": evt_type, **event
        })

        # Push to dashboard
        event["source"] = "NDR"
        event["src_ip"] = ip_str(src_ip)
        event["dst_ip"] = ip_str(dst_ip)
        self.push_event(event)

        if alert_level >= ALERT_WARNING:
            self.log.write_critical(msg)
            self.alert.send(alert_level, evt_name, msg)
        else:
            self.log.write_general(msg)

    def _check_correlations(self, pid: int, event: dict):
        """Cross-correlate EDR and NDR events for advanced threat detection."""
        now = time.time()

        # Scenario 1: Process exec + outbound connection = potential C2C
        pid_events = self.edr_events.get(pid, [])
        recent = [e for e in pid_events if now - e["time"] < CORRELATION_WINDOW_SECS]
        has_exec = any(e["type"] == EVT_PROCESS_EXEC for e in recent)
        has_net = any(e["type"] == EVT_NET_CONNECT for e in recent)

        if has_exec and has_net:
            msg = f"XDR CORRELATION: pid={pid} exec+connect in {CORRELATION_WINDOW_SECS}s (potential C2C)"
            self.log.write_critical(msg)
            self.alert.send(ALERT_WARNING, "CORRELATION", msg)
            self.push_event({
                "source": "CORRELATION", "alert_level": ALERT_WARNING,
                "mitre_id": "T1071",
                "message": msg, "event_type": "c2c_suspect", "pid": pid,
            })

        # Scenario 2: Beacon detection (repeated connections to same IP)
        for _ip, count in list(self.connect_counts.items()):
            if count >= BEACON_DETECT_COUNT:
                msg = f"XDR BEACON DETECTED: {ip_str(_ip)} hit {count} times"
                self.log.write_critical(msg)
                self.alert.send(ALERT_CRITICAL, "BEACON", msg)
                self.push_event({
                    "source": "CORRELATION", "alert_level": ALERT_CRITICAL,
                    "mitre_id": "T1071.001",
                    "message": msg, "event_type": "beacon",
                    "target_ip": ip_str(_ip),
                })
                self.connect_counts[_ip] = 0  # reset

        # ── APT Kill Chain Scenarios ─────────────────────

        # Track event categories across all PIDs for kill chain detection
        all_recent = []
        for p_events in self.edr_events.values():
            all_recent.extend(
                e for e in p_events if now - e["time"] < CORRELATION_WINDOW_SECS * 5
            )

        # Categorize events
        cats = set()
        for e in all_recent:
            reason = e.get("reason", "")
            mitre = e.get("mitre_id", "")
            alert_lv = e.get("alert_level", 0)

            if "PRIV_ESCALATION" in reason or "T1548" in mitre:
                cats.add("priv_escalation")
            if e["type"] == EVT_NET_CONNECT:
                cats.add("net_connect")
            if "SENSITIVE_FILE" in reason or "T1005" in mitre:
                cats.add("sensitive_file")
            if "DNS_TUNNEL" in reason or "T1572" in mitre:
                cats.add("dns_tunnel")
            if "DGA" in reason:
                cats.add("dga")
            if "REVERSE_SHELL" in reason or "T1059" in mitre:
                cats.add("reverse_shell")
            if "CRONTAB" in reason or "T1053" in mitre:
                cats.add("persistence")
            if "LOG_TAMPER" in reason or "T1070" in mitre:
                cats.add("anti_forensics")
            if "LOLBIN" in reason:
                cats.add("lolbin")
            if alert_lv >= 3:
                cats.add("critical")

        # Scenario 3: Privilege escalation + outbound connection
        if "priv_escalation" in cats and "net_connect" in cats:
            key = "apt_privesc_c2"
            if key not in self._apt_alerts_seen:
                self._apt_alerts_seen.add(key)
                msg = (
                    "APT 킬체인: 권한 상승 → 외부 연결 감지! "
                    "(초기 침투 → 권한 상승 → C2 설정)"
                )
                self.log.write_critical(msg)
                self.alert.send(ALERT_CRITICAL, "APT_KILL_CHAIN", msg)
                self.push_event({
                    "source": "CORRELATION", "alert_level": ALERT_CRITICAL,
                    "mitre_id": "T1548",
                    "message": msg, "event_type": "apt_kill_chain",
                    "chain": "priv_escalation+c2",
                })

        # Scenario 4: Sensitive file access + DNS tunneling (data exfil)
        if "sensitive_file" in cats and ("dns_tunnel" in cats or "dga" in cats):
            key = "apt_exfil_dns"
            if key not in self._apt_alerts_seen:
                self._apt_alerts_seen.add(key)
                msg = (
                    "APT 킬체인: 민감 파일 접근 → DNS 유출 감지! "
                    "(데이터 수집 → DNS 터널링 유출)"
                )
                self.log.write_critical(msg)
                self.alert.send(ALERT_CRITICAL, "APT_KILL_CHAIN", msg)
                self.push_event({
                    "source": "CORRELATION", "alert_level": ALERT_CRITICAL,
                    "mitre_id": "T1048.001",
                    "message": msg, "event_type": "apt_kill_chain",
                    "chain": "data_collection+dns_exfil",
                })

        # Scenario 5: Persistence + reverse shell + anti-forensics
        if "persistence" in cats and "reverse_shell" in cats:
            key = "apt_persist_shell"
            if key not in self._apt_alerts_seen:
                self._apt_alerts_seen.add(key)
                msg = (
                    "APT 킬체인: 지속성 확보 → 리버스 쉘 감지! "
                    "(crontab/systemd → 리버스 쉘 연결)"
                )
                self.log.write_critical(msg)
                self.alert.send(ALERT_CRITICAL, "APT_KILL_CHAIN", msg)
                self.push_event({
                    "source": "CORRELATION", "alert_level": ALERT_CRITICAL,
                    "mitre_id": "T1053.003",
                    "message": msg, "event_type": "apt_kill_chain",
                    "chain": "persistence+reverse_shell",
                })

        # Scenario 6: Anti-forensics (log tampering detected)
        if "anti_forensics" in cats and "critical" in cats:
            key = "apt_anti_forensics"
            if key not in self._apt_alerts_seen:
                self._apt_alerts_seen.add(key)
                msg = (
                    "APT 킬체인: CRITICAL 이벤트 + 흔적 제거 시도 감지! "
                    "(공격 후 로그 삭제/타임스탬프 조작)"
                )
                self.log.write_critical(msg)
                self.alert.send(ALERT_CRITICAL, "APT_KILL_CHAIN", msg)
                self.push_event({
                    "source": "CORRELATION", "alert_level": ALERT_CRITICAL,
                    "mitre_id": "T1070",
                    "message": msg, "event_type": "apt_kill_chain",
                    "chain": "attack+anti_forensics",
                })

        # Scenario 7: LOLBin chain (multiple LOLBin commands in sequence)
        lolbin_count = sum(1 for e in all_recent if "LOLBIN" in e.get("reason", ""))
        if lolbin_count >= 3:
            key = "apt_lolbin_chain"
            if key not in self._apt_alerts_seen:
                self._apt_alerts_seen.add(key)
                msg = (
                    f"APT 킬체인: LOLBin 연쇄 사용 감지! "
                    f"({lolbin_count}개 LOLBin 명령 5분 내 실행)"
                )
                self.log.write_critical(msg)
                self.alert.send(ALERT_CRITICAL, "APT_KILL_CHAIN", msg)
                self.push_event({
                    "source": "CORRELATION", "alert_level": ALERT_CRITICAL,
                    "mitre_id": "T1218",
                    "message": msg, "event_type": "apt_kill_chain",
                    "chain": "lolbin_chain",
                })

        # Periodic cleanup
        if now - self.last_cleanup > 60:
            self._cleanup_old_events()
            self.last_cleanup = now

    def _cleanup_old_events(self):
        cutoff = time.time() - CORRELATION_WINDOW_SECS * 2
        with self._lock:
            for pid in list(self.edr_events.keys()):
                self.edr_events[pid] = [
                    e for e in self.edr_events[pid] if e["time"] > cutoff
                ]
                if not self.edr_events[pid]:
                    del self.edr_events[pid]
            for _ip in list(self.ndr_events.keys()):
                self.ndr_events[_ip] = [
                    e for e in self.ndr_events[_ip] if e["time"] > cutoff
                ]
                if not self.ndr_events[_ip]:
                    del self.ndr_events[_ip]
            self.exec_count = 0
            self.connect_counts.clear()
            self._apt_alerts_seen.clear()  # Reset kill chain alerts each cycle

