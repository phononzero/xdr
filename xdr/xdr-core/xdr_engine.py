#!/usr/bin/env python3
"""
XDR Core Engine — Correlates EDR + NDR events, manages alerts and responses.
Loads eBPF programs, reads ring buffers via ctypes/libbpf, performs
correlation analysis, triggers blocking actions, and sends alerts.
Includes Flask web dashboard on 127.0.0.1:29992.

Split into engine/ subpackage for modularity.
"""

import os
import sys
import time
import signal
import ctypes
import struct
import socket
import logging
import subprocess
from pathlib import Path
from threading import Thread, Event, Lock
from collections import OrderedDict

# ---- Local modules ----
from blocklist_store import BlocklistStore
from edr_detector import EDRDetector
from yara_scanner import YARAScanner, create_default_rules
from integrity_monitor import IntegrityMonitor
from package_monitor import PackageMonitor
from ssl_probe import SSLProbe
from dns_monitor import DNSMonitor
from tls_fingerprint import TLSFingerprint
from file_audit import FileAudit
from threat_intel import ThreatIntelFeed
from forensic_collector import ForensicCollector
from self_protect import SelfProtect
import web_dashboard

# ---- Engine sub-modules ----
from engine import (
    EdrEvent, NdrEvent,
    ALERT_INFO, ALERT_WARNING, ALERT_CRITICAL,
    EVT_PROCESS_EXEC, EVT_NET_CONNECT, EVT_MODULE_LOAD,
    EVT_PROCESS_EXIT, EVT_MEMFD_CREATE, EVT_PTRACE,
    RingBufferPoller, get_map_fd_by_name,
    LogManager, AlertSystem, CorrelationEngine, ip_str,
)

# ---- Configuration ----
from config_loader import get_config as _get_config
from nic_manager import resolve_nic as _resolve_nic
_cfg = _get_config()
XDR_DIR = Path(_cfg["engine"]["xdr_dir"])
NIC_INTERFACE = _resolve_nic(_cfg["engine"]["nic_interface"])
DASHBOARD_PORT = _cfg["engine"]["dashboard_port"]

shutdown_event = Event()


# ===============================================================
# XDR Engine — Main
# ===============================================================

class XDREngine:
    """Main XDR engine that ties everything together."""

    # Cache limits and TTL (2GB budget: ~1.5GB proc + ~0.5GB conn)
    CONN_CACHE_MAX = 500_000
    CONN_CACHE_TTL = 600       # 10 minutes
    PROC_CACHE_MAX = 1_500_000
    PROC_CACHE_TTL = 1800      # 30 minutes

    def __init__(self):
        self.log_manager = LogManager()
        self.alert_system = AlertSystem()
        self.correlator = CorrelationEngine(self.log_manager, self.alert_system,
                                             push_event_fn=web_dashboard.push_event)
        self.blocklist = BlocklistStore()
        self.detector = EDRDetector(self.blocklist)
        self.yara = YARAScanner()
        # Process lineage (real-time tree + attack chain detection)
        from edr_detector.process_lineage import ProcessLineage
        self.lineage = ProcessLineage()
        self.rb_poller = None
        self.running = True

        # eBPF event caches for enriching ss/proc results (OrderedDict for O(1) LRU eviction)
        # conn_cache: {(src_ip, src_port, dst_ip, dst_port) → info}
        self.conn_cache = OrderedDict()
        self._conn_lock = Lock()
        # proc_cache: {pid → info}
        self.proc_cache = OrderedDict()
        self._proc_lock = Lock()

        # Debug counters
        self._edr_event_count = 0
        self._ndr_event_count = 0
        self._edr_errors = []
        self._poll_count = 0

        # Phase 2 modules
        self.integrity = IntegrityMonitor(push_event_fn=web_dashboard.push_event)
        self.packages = PackageMonitor(push_event_fn=web_dashboard.push_event)
        self.ssl_probe = SSLProbe(edr_detector=self.detector,
                                  push_event_fn=web_dashboard.push_event)
        self.dns_monitor = DNSMonitor(push_event_fn=web_dashboard.push_event)
        self.tls_fingerprint = TLSFingerprint(push_event_fn=web_dashboard.push_event)
        self.file_audit = FileAudit(push_event_fn=web_dashboard.push_event)
        self.threat_intel = ThreatIntelFeed(
            push_event_fn=web_dashboard.push_event,
            blocklist_store=self.blocklist)
        self.forensics = ForensicCollector()
        self.self_protect = SelfProtect(push_event_fn=web_dashboard.push_event)

    def run(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [XDR] %(message)s"
        )
        logging.info("XDR Engine starting...")

        # Register signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        # Clean up previous BPF state
        self._cleanup_previous_state()

        # Start log cleanup thread
        cleanup_thread = Thread(target=self._log_cleanup_loop, daemon=True)
        cleanup_thread.start()

        # Load eBPF programs
        self._load_ebpf_programs()

        # Sync blocklists to BPF maps
        self.blocklist.sync_to_bpf()

        # Create default YARA rules if none exist
        create_default_rules()
        self.yara.reload_rules()

        # Initialize web dashboard
        web_dashboard.init_dashboard(self.blocklist)
        web_dashboard.set_edr_detector(self.detector)
        web_dashboard.set_integrity_monitor(self.integrity)
        web_dashboard.set_package_monitor(self.packages)
        web_dashboard.set_dns_monitor(self.dns_monitor)
        web_dashboard.set_tls_fingerprint(self.tls_fingerprint)
        web_dashboard.set_file_audit(self.file_audit)
        web_dashboard.set_ssl_probe(self.ssl_probe)
        web_dashboard.set_xdr_engine(self)

        # Start kernel update checker (every hour)
        web_dashboard.start_kernel_checker(interval_secs=3600)

        # Start Phase 2 background services
        self.integrity.start()
        self.packages.start()
        self.ssl_probe.start()
        self.dns_monitor.start()
        self.file_audit.start()
        logging.info("Phase 2 modules started: integrity, packages, ssl_probe, dns, file_audit")

        # Start Phase 8 threat intelligence feed
        self.threat_intel.start()
        logging.info("Phase 8: Threat intelligence feed started")

        # Start Phase 10 self-protection
        self.self_protect.start()
        logging.info("Phase 10: Self-protection started")

        # Start BPF Guard — restrict bpf() access to XDR only
        try:
            from bpf_guard import BPFGuard
            self._bpf_guard = BPFGuard()
            if self._bpf_guard.load():
                self._bpf_guard.register_pid(os.getpid())
                # Register child thread PIDs if needed
                self._bpf_guard.enable()
                logging.info("BPF Guard: eBPF access restricted to XDR only")
            else:
                logging.warning("BPF Guard: failed to load — eBPF access unrestricted")
        except Exception as e:
            logging.warning(f"BPF Guard: unavailable ({e}) — eBPF access unrestricted")

        # Start Phase 5 memory forensics scanner
        mem_scan_thread = Thread(target=self._memory_scan_loop, daemon=True)
        mem_scan_thread.start()
        logging.info("Phase 5: Memory forensics scanner started (60s interval)")

        # Start Flask dashboard in background thread
        dashboard_thread = Thread(target=self._run_dashboard, daemon=True)
        dashboard_thread.start()

        # Initialize ring buffer polling
        self._init_ring_buffers()

        # ── Kernel Hardening (after all eBPF loaded) ─────────
        # Runs in background: verify HW drivers → scan modules → sysctl → lockdown
        try:
            from lockdown_manager import LockdownManager
            self._lockdown_mgr = LockdownManager(
                push_event_fn=web_dashboard.push_event,
                max_retries=5, retry_interval=10
            )
            self._lockdown_mgr.execute()  # Background thread
            logging.info("Lockdown Manager: pre-lockdown verification started")
        except Exception as e:
            logging.warning(f"Lockdown Manager unavailable: {e}")

        # Main event loop
        logging.info("XDR Engine running. Monitoring...")
        logging.info(f"Dashboard: http://127.0.0.1:{DASHBOARD_PORT}")
        self.log_manager.write_critical("XDR Engine started")
        self.alert_system.send(ALERT_INFO, "XDR", "XDR Engine started successfully")

        while self.running and not shutdown_event.is_set():
            try:
                self._poll_events()
            except Exception as e:
                logging.error(f"Event poll error: {e}")
                time.sleep(1)

        self.log_manager.write_critical("XDR Engine stopped")
        if self.rb_poller:
            self.rb_poller.free()
        self.log_manager.close()
        logging.info("XDR Engine stopped.")

    def _cleanup_previous_state(self):
        """Clean up previous BPF pins and XDP attachments."""
        edr_pin_path = Path("/sys/fs/bpf/xdr_edr")
        if edr_pin_path.exists():
            logging.info("Cleaning up previous EDR pins...")
            try:
                subprocess.run(["rm", "-rf", str(edr_pin_path)],
                               check=True, capture_output=True, timeout=5)
            except Exception as e:
                logging.warning(f"EDR pin cleanup failed: {e}")

        # Detach XDP from NIC
        try:
            result = subprocess.run(
                ["ip", "link", "show", NIC_INTERFACE],
                capture_output=True, text=True, timeout=3
            )
            if "xdp" in result.stdout.lower():
                logging.info(f"Detaching previous XDP from {NIC_INTERFACE}...")
                subprocess.run(
                    ["ip", "link", "set", "dev", NIC_INTERFACE, "xdp", "off"],
                    check=True, capture_output=True, timeout=5
                )
        except Exception as e:
            logging.debug(f"XDP detach: {e}")

    def _load_ebpf_programs(self):
        """Load eBPF EDR and XDP NDR programs using bpftool."""
        logging.info("Loading eBPF programs...")

        edr_obj = XDR_DIR / "ebpf-edr" / "edr.bpf.o"
        ndr_obj = XDR_DIR / "xdp-ndr" / "ndr.bpf.o"

        if edr_obj.exists():
            try:
                subprocess.run(
                    ["/usr/sbin/bpftool", "prog", "loadall", str(edr_obj),
                     "/sys/fs/bpf/xdr_edr", "autoattach"],
                    check=True, capture_output=True
                )
                logging.info("EDR eBPF programs loaded + attached (autoattach)")
            except subprocess.CalledProcessError as e:
                logging.warning(f"EDR load failed: {e.stderr.decode()}")
        else:
            logging.warning(f"EDR object not found: {edr_obj}. Run build-ebpf.sh first.")

        if ndr_obj.exists():
            try:
                subprocess.run(
                    ["ip", "link", "set", "dev", NIC_INTERFACE, "xdp", "obj",
                     str(ndr_obj), "sec", "xdp"],
                    check=True, capture_output=True
                )
                logging.info(f"NDR XDP attached to {NIC_INTERFACE}")
            except subprocess.CalledProcessError as e:
                logging.warning(f"NDR attach failed: {e.stderr.decode()}")
        else:
            logging.warning(f"NDR object not found: {ndr_obj}. Run build-ebpf.sh first.")

    def _init_ring_buffers(self):
        """Initialize ring buffer polling via libbpf ctypes."""
        self.rb_poller = RingBufferPoller()

        if not self.rb_poller._lib:
            logging.warning("Ring buffer polling not available (libbpf missing)")
            return

        edr_fd = get_map_fd_by_name("events")
        if edr_fd >= 0:
            if self.rb_poller.attach_ringbuf(edr_fd, self._edr_callback):
                logging.info("EDR ring buffer attached")
            else:
                logging.warning("Failed to attach EDR ring buffer")
        else:
            logging.warning("EDR events map not found")

        ndr_fd = get_map_fd_by_name("ndr_events")
        if ndr_fd >= 0:
            if self.rb_poller.attach_ringbuf(ndr_fd, self._ndr_callback):
                logging.info("NDR ring buffer attached")
            else:
                logging.warning("Failed to attach NDR ring buffer")
        else:
            logging.warning("NDR events map not found")

    def _get_parent_info(self, ppid: int) -> list:
        """Get parent process chain from /proc (up to 5 levels)."""
        chain = []
        visited = set()
        current = ppid
        for _ in range(5):
            if current <= 1 or current in visited:
                break
            visited.add(current)
            try:
                with open(f"/proc/{current}/comm") as f:
                    pcomm = f.read().strip()
                ppath = ""
                try:
                    ppath = os.readlink(f"/proc/{current}/exe")
                except OSError:
                    pass
                chain.append({"pid": current, "comm": pcomm, "path": ppath})
                # Get next parent
                with open(f"/proc/{current}/status") as f:
                    for line in f:
                        if line.startswith("PPid:"):
                            current = int(line.split(":")[1].strip())
                            break
                    else:
                        break
            except (OSError, PermissionError, ValueError):
                break
        return chain

    def _edr_callback(self, ctx, data, size):
        """Callback for EDR ring buffer events."""
        self._edr_event_count += 1
        try:
            if size < ctypes.sizeof(EdrEvent):
                return 0
            evt = EdrEvent.from_buffer_copy(
                ctypes.string_at(data, ctypes.sizeof(EdrEvent))
            )
            now = time.time()
            comm_str = evt.comm.decode("utf-8", errors="replace").rstrip("\x00")
            fname_str = evt.filename.decode("utf-8", errors="replace").rstrip("\x00")
            # Decode argv from eBPF (kernel-captured, no race condition)
            argv_str = evt.argv.decode("utf-8", errors="replace").rstrip("\x00")

            # Resolve parent process name
            ppid_comm = ""
            if evt.ppid:
                cached_parent = self.proc_cache.get(evt.ppid)
                if cached_parent:
                    ppid_comm = cached_parent.get("comm", "")
                else:
                    try:
                        with open(f"/proc/{evt.ppid}/comm") as f:
                            ppid_comm = f.read().strip()
                    except OSError:
                        pass

            # Use eBPF argv if available, fallback to /proc/cmdline
            cmdline = argv_str if argv_str else ""
            if not cmdline and evt.event_type == EVT_PROCESS_EXEC:
                try:
                    with open(f"/proc/{evt.pid}/cmdline", "rb") as f:
                        raw = f.read(4096)
                    if raw:
                        cmdline = raw.replace(b"\x00", b" ").decode(
                            "utf-8", errors="ignore").strip()
                except OSError:
                    cmdline = fname_str

            event = {
                "timestamp_ns": evt.timestamp_ns,
                "pid": evt.pid,
                "tgid": evt.tgid,
                "uid": evt.uid,
                "gid": evt.gid,
                "event_type": evt.event_type,
                "alert_level": evt.alert_level,
                "ret_code": evt.ret_code,
                "ppid": evt.ppid,
                "ppid_comm": ppid_comm,
                "comm": comm_str,
                "filename": fname_str,
                "cmdline": cmdline,
                "dst_ip": evt.dst_ip,
                "dst_port": evt.dst_port,
            }

            # ── Cache updates ──
            if evt.event_type == EVT_PROCESS_EXEC:
                # Update proc_cache
                with self._proc_lock:
                    self.proc_cache[evt.pid] = {
                        "comm": comm_str,
                        "exe": fname_str,
                        "cmdline": cmdline,
                        "uid": evt.uid,
                        "ppid": evt.ppid,
                        "ppid_comm": ppid_comm,
                        "last_seen": now,
                    }
                    while len(self.proc_cache) > self.PROC_CACHE_MAX:
                        self.proc_cache.popitem(last=False)

                # Update process lineage + check attack chains
                chain_alert = self.lineage.on_exec(
                    evt.pid, evt.ppid, comm_str, fname_str, cmdline, evt.uid
                )
                if chain_alert:
                    chain_alert["source"] = "DETECTOR"
                    chain_alert["pid"] = evt.pid
                    chain_alert["comm"] = comm_str
                    chain_alert["ppid"] = evt.ppid
                    chain_alert["ppid_comm"] = ppid_comm
                    chain_alert["cmdline"] = cmdline
                    web_dashboard.push_event(chain_alert)
                    if chain_alert.get("alert_level", 0) >= 2:
                        self.alert_system.send(
                            chain_alert["alert_level"],
                            chain_alert.get("reason", "ATTACK_CHAIN"),
                            chain_alert.get("detail", ""))

            elif evt.event_type == EVT_PROCESS_EXIT:
                # Remove from proc_cache + lineage on exit
                with self._proc_lock:
                    self.proc_cache.pop(evt.pid, None)
                self.lineage.on_exit(evt.pid)
                return 0  # No further processing for exit events

            elif evt.event_type == EVT_NET_CONNECT and evt.dst_ip:
                # Skip localhost connections (prevents beacon false positives)
                try:
                    ip_dotted = socket.inet_ntoa(struct.pack("!I", evt.dst_ip))
                except Exception:
                    ip_dotted = ""
                # Check both byte orders (eBPF may store in host or network order)
                if ip_dotted.startswith("127.") or ip_dotted.endswith(".127") or ip_dotted == "0.0.0.0":
                    return 0

                # Update conn_cache
                with self._conn_lock:
                    key = (0, 0, evt.dst_ip, evt.dst_port)
                    self.conn_cache[key] = {
                        "pid": evt.pid,
                        "comm": comm_str,
                        "exe": fname_str,
                        "uid": evt.uid,
                        "start_time": now,
                        "end_time": None,
                    }
                    dst_key = (evt.dst_ip, evt.dst_port)
                    self.conn_cache[dst_key] = self.conn_cache[key]
                    while len(self.conn_cache) > self.CONN_CACHE_MAX:
                        self.conn_cache.popitem(last=False)

                # Threat Intelligence IP check
                ti_alert = self.threat_intel.check_ip(ip_dotted)
                if ti_alert:
                    ti_alert["pid"] = evt.pid
                    ti_alert["comm"] = comm_str
                    ti_alert["detail"] = (
                        f"위협 인텔리전스: 악성 IP 연결 — "
                        f"{comm_str}({evt.pid}) → {ip_dotted}:{evt.dst_port}"
                    )
                    web_dashboard.push_event(ti_alert)
                    self.alert_system.send(3, "TI_MALICIOUS_IP", ti_alert["detail"])

            elif evt.event_type == EVT_FILE_OPEN and fname_str:
                # Sensitive file access monitoring (FIM)
                SENSITIVE_FILES = (
                    "shadow", "passwd", "sudoers", "gshadow",
                    "authorized_keys", "id_rsa", "id_ed25519",
                    ".bash_history", ".ssh",
                )
                SENSITIVE_DIRS = (
                    "/etc/ssh/", "/root/.ssh/", "/etc/pam.d/",
                )
                is_sensitive = False
                for sf in SENSITIVE_FILES:
                    if sf in fname_str:
                        is_sensitive = True
                        break
                if not is_sensitive:
                    for sd in SENSITIVE_DIRS:
                        if sd in fname_str:
                            is_sensitive = True
                            break
                if is_sensitive:
                    event["source"] = "DETECTOR"
                    event["reason"] = "SENSITIVE_FILE_ACCESS"
                    event["mitre_id"] = "T1005"
                    event["alert_level"] = 3 if evt.uid != 0 else 2
                    event["detail"] = (
                        f"민감 파일 접근: {fname_str} | "
                        f"프로세스: {comm_str} pid={evt.pid} "
                        f"ppid={evt.ppid}({ppid_comm}) uid={evt.uid}"
                    )
                    web_dashboard.push_event(event)
                    if event["alert_level"] >= 3:
                        self.alert_system.send(3, "SENSITIVE_FILE", event["detail"])

            # ── Advanced detection pipeline ──
            # Skip detection for XDR's own child processes (prevents feedback loop)
            _self_pid = os.getpid()
            if evt.ppid == _self_pid or comm_str == "notify-send":
                return 0  # Already cached above, skip detection

            if evt.event_type == EVT_PROCESS_EXEC:
                det_result = self.detector.check_exec(event)
                if det_result:
                    det_result["source"] = "DETECTOR"
                    # Enrich with process info
                    det_result.setdefault("comm", comm_str)
                    det_result.setdefault("ppid", evt.ppid)
                    det_result.setdefault("ppid_comm", ppid_comm)
                    det_result.setdefault("path", fname_str)
                    det_result.setdefault("uid", evt.uid)
                    # Add parent chain info
                    parent_chain = self._get_parent_info(evt.ppid)
                    det_result["parent_chain"] = parent_chain
                    # Enrich detail with full process context
                    chain_str = " → ".join(
                        f"{p['comm']}({p['pid']})" for p in parent_chain
                    ) if parent_chain else ""
                    orig_detail = det_result.get("detail", "")
                    det_result["detail"] = (
                        f"{orig_detail} | 프로세스: {comm_str} "
                        f"pid={evt.pid} ppid={evt.ppid}({ppid_comm}) "
                        f"path={fname_str}"
                        + (f" | 부모체인: {chain_str}" if chain_str else "")
                    )
                    web_dashboard.push_event(det_result)
                    if det_result.get("alert_level", 0) >= 2:
                        self.alert_system.send(
                            det_result["alert_level"],
                            det_result.get("reason", "DETECTION"),
                            det_result.get("detail", ""))

                # YARA scan on exec (skip if whitelisted — including parent chain)
                if fname_str:
                    wl_scopes = self.detector._get_whitelist_scopes(comm_str, fname_str)
                    if "all" not in wl_scopes:
                        # Also check parent chain for YARA whitelist
                        wl_scopes |= self.detector._check_parent_whitelist(evt.pid, evt.ppid)
                    if "all" not in wl_scopes:
                        yara_result = self.yara.scan_exec_event(fname_str)
                        if yara_result:
                            yara_result["source"] = "YARA"
                            yara_result["pid"] = evt.pid
                            yara_result["comm"] = comm_str
                            yara_result["ppid"] = evt.ppid
                            yara_result["ppid_comm"] = ppid_comm
                            yara_result["path"] = fname_str
                            parent_chain = self._get_parent_info(evt.ppid)
                            yara_result["parent_chain"] = parent_chain
                            web_dashboard.push_event(yara_result)
                            self.alert_system.send(
                                yara_result["alert_level"],
                                "YARA", yara_result["detail"])
            elif evt.event_type == EVT_MEMFD_CREATE:
                # Fileless malware: memfd_create detected at kernel level
                event["source"] = "DETECTOR"
                event["reason"] = "MEMFD_CREATE"
                event["mitre_id"] = "T1620"
                event["detail"] = (
                    f"커널 감지: memfd_create 호출 | "
                    f"프로세스: {comm_str} pid={evt.pid} ppid={evt.ppid}({ppid_comm}) "
                    f"이름={fname_str}"
                )
                event["alert_level"] = 3  # CRITICAL
                web_dashboard.push_event(event)
                self.alert_system.send(3, "MEMFD_CREATE", event["detail"])

            elif evt.event_type == EVT_PTRACE:
                # Process injection: ptrace detected at kernel level
                target_pid = evt.dst_ip  # reused field
                request = evt.dst_port   # reused field
                req_names = {4: "POKETEXT", 5: "POKEDATA", 16: "ATTACH", 0x4206: "SEIZE"}
                req_name = req_names.get(request, f"REQ_{request}")
                event["source"] = "DETECTOR"
                event["reason"] = "PTRACE"
                event["mitre_id"] = "T1055.008"
                event["detail"] = (
                    f"커널 감지: ptrace {req_name} | "
                    f"추적자: {comm_str}({evt.pid}) → 대상: pid={target_pid}"
                )
                if evt.alert_level >= 2:
                    web_dashboard.push_event(event)
                    if evt.alert_level >= 3:
                        self.alert_system.send(3, "PTRACE_INJECTION", event["detail"])

            elif evt.event_type == EVT_MODULE_LOAD:
                # Kernel module loading detected (init_module/finit_module)
                params_str = fname_str  # Module params stored in filename field
                event["source"] = "DETECTOR"
                event["reason"] = "KERNEL_MODULE_LOAD"
                event["mitre_id"] = "T1547.006"
                event["alert_level"] = 3  # CRITICAL — always suspicious
                event["detail"] = (
                    f"커널 모듈 로딩 감지: {comm_str}({evt.pid}) "
                    f"ppid={evt.ppid}({ppid_comm}) "
                    f"파라미터={params_str if params_str else '(없음)'}"
                )
                web_dashboard.push_event(event)
                self.alert_system.send(3, "KERNEL_MODULE_LOAD", event["detail"])

            else:
                # Non-exec events: check behavioral sequences
                self.detector.check_event(event)

            self.correlator.process_edr_event(event)
        except Exception as e:
            logging.debug(f"EDR callback error: {e}")
        return 0

    def _activate_kernel_hardening(self):
        """Apply sysctl hardening + kernel lockdown after eBPF programs are loaded.

        Order: sysctl → lockdown (lockdown must be LAST since it's irreversible)
        """
        # 1. sysctl hardening
        sysctl_settings = {
            "kernel.unprivileged_bpf_disabled": "2",
            "kernel.kexec_load_disabled": "1",
            "kernel.kptr_restrict": "2",
            "kernel.dmesg_restrict": "1",
            "kernel.perf_event_paranoid": "3",
        }
        for key, val in sysctl_settings.items():
            try:
                subprocess.run(
                    ["sysctl", "-w", f"{key}={val}"],
                    capture_output=True, timeout=5
                )
            except Exception:
                pass
        logging.info("Kernel hardening: sysctl settings applied")

        # 2. Activate kernel lockdown (integrity mode)
        try:
            lockdown_path = Path("/sys/kernel/security/lockdown")
            if lockdown_path.exists():
                current = lockdown_path.read_text().strip()
                if "[none]" in current:
                    lockdown_path.write_text("integrity")
                    logging.info("Kernel hardening: lockdown activated (integrity)")
                elif "[integrity]" in current:
                    logging.info("Kernel hardening: lockdown already active (integrity)")
                else:
                    logging.info(f"Kernel hardening: lockdown status: {current}")
        except PermissionError:
            logging.warning("Kernel hardening: no permission to set lockdown (not root?)")
        except OSError as e:
            # "Operation not permitted" = lockdown already at integrity+
            if "not permitted" in str(e).lower():
                logging.info("Kernel hardening: lockdown already active")
            else:
                logging.warning(f"Kernel hardening: lockdown error: {e}")

    def get_conn_cache(self):
        """Return conn_cache copy for API enrichment, auto-expire old entries."""
        now = time.time()
        with self._conn_lock:
            expired = [k for k, v in self.conn_cache.items()
                       if now - v["start_time"] > self.CONN_CACHE_TTL]
            for k in expired:
                del self.conn_cache[k]
            return dict(self.conn_cache)

    def get_proc_cache(self):
        """Return proc_cache copy for API enrichment, auto-expire old entries."""
        now = time.time()
        with self._proc_lock:
            expired = [k for k, v in self.proc_cache.items()
                       if now - v["last_seen"] > self.PROC_CACHE_TTL]
            for k in expired:
                del self.proc_cache[k]
            return dict(self.proc_cache)

    def _ndr_callback(self, ctx, data, size):
        """Callback for NDR ring buffer events."""
        try:
            if size < ctypes.sizeof(NdrEvent):
                return 0
            evt = NdrEvent.from_buffer_copy(
                ctypes.string_at(data, ctypes.sizeof(NdrEvent))
            )
            event = {
                "timestamp_ns": evt.timestamp_ns,
                "src_ip": evt.src_ip,
                "dst_ip": evt.dst_ip,
                "src_port": evt.src_port,
                "dst_port": evt.dst_port,
                "protocol": evt.protocol,
                "alert_level": evt.alert_level,
                "action": evt.action,
                "event_type": evt.event_type,
                "pkt_len": evt.pkt_len,
            }
            self.correlator.process_ndr_event(event)
        except Exception as e:
            logging.debug(f"NDR callback error: {e}")
        return 0

    def _poll_events(self):
        """Poll eBPF ring buffers for events."""
        self._poll_count += 1
        if self.rb_poller and self.rb_poller._rb:
            self.rb_poller.poll(timeout_ms=100)
        else:
            time.sleep(1)

    def _run_dashboard(self):
        """Run Flask dashboard in background thread with TLS 1.3."""
        import ssl

        cert_dir = Path("/opt/xdr/certs")
        cert_file = cert_dir / "xdr.pem"
        key_file = cert_dir / "xdr-key.pem"

        ssl_ctx = None
        if cert_file.exists() and key_file.exists():
            try:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                try:
                    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                except AttributeError:
                    pass
                ssl_ctx.load_cert_chain(str(cert_file), str(key_file))
                logging.info("Dashboard: TLS enabled (cert: %s)", cert_file)
            except Exception as e:
                logging.warning(f"Dashboard: TLS setup failed, falling back to HTTP: {e}")
                ssl_ctx = None
        else:
            logging.warning("Dashboard: No TLS certs found at %s, running HTTP", cert_dir)

        try:
            web_dashboard.app.run(
                host="127.0.0.1",
                port=DASHBOARD_PORT,
                debug=False,
                use_reloader=False,
                threaded=True,
                ssl_context=ssl_ctx,
            )
        except Exception as e:
            logging.error(f"Dashboard server error: {e}")

    def _memory_scan_loop(self):
        """Periodic memory forensics scan — detect RWX, deleted mappings, injection."""
        from edr_detector.detectors.memory_scanner import scan_all_processes
        # Wait for engine to fully initialize
        shutdown_event.wait(30)
        xdr_pid = os.getpid()
        _seen_alerts = set()  # Deduplicate repeated alerts for same pid+region

        while not shutdown_event.is_set():
            try:
                alerts = scan_all_processes(xdr_pid=xdr_pid)
                for alert in alerts:
                    # Deduplicate: same pid + reason in this cycle
                    dedup_key = (alert["pid"], alert["reason"])
                    if dedup_key in _seen_alerts:
                        continue
                    _seen_alerts.add(dedup_key)

                    web_dashboard.push_event(alert)
                    if alert.get("alert_level", 0) >= 3:
                        self.alert_system.send(
                            alert["alert_level"],
                            alert.get("reason", "MEMORY_SCAN"),
                            alert.get("detail", ""))
                        # Auto forensic collection on CRITICAL
                        try:
                            self.forensics.collect(alert)
                        except Exception:
                            pass

                # Reset dedup set each cycle
                _seen_alerts.clear()
            except Exception as e:
                logging.debug(f"Memory scan error: {e}")
            shutdown_event.wait(60)  # Scan every 60 seconds

    def _log_cleanup_loop(self):
        """Periodic log cleanup thread."""
        while not shutdown_event.is_set():
            try:
                self.log_manager.cleanup_general()
            except Exception as e:
                logging.error(f"Log cleanup error: {e}")
            shutdown_event.wait(3600)

    def _handle_signal(self, signum, frame):
        logging.info(f"Received signal {signum}, shutting down...")
        self.running = False
        shutdown_event.set()


# Backward compat: keep _ip_str accessible from this module
_ip_str = ip_str


def main():
    engine = XDREngine()
    engine.run()


if __name__ == "__main__":
    main()
