#!/usr/bin/env python3
"""
XDR Self-Protection — Anti-Tampering module.

Protects XDR agent from:
  - Binary/config file modification
  - Process termination attempts
  - Settings tampering

MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
"""

import os
import hashlib
import logging
import json
import time
from datetime import datetime
from pathlib import Path
from threading import Thread, Event, Lock

logger = logging.getLogger("xdr.self_protect")

XDR_DIR = Path("/opt/xdr")
HASH_STORE = XDR_DIR / "self_protect_hashes.json"

# Critical files to protect
CRITICAL_FILES = [
    "xdr-core/xdr_engine.py",
    "xdr-core/edr_detector/__init__.py",
    "xdr-core/edr_detector/policy.py",
    "xdr-core/edr_detector/detectors/rules.py",
    "xdr-core/edr_detector/detectors/lolbins.py",
    "xdr-core/blocklist_store.py",
    "xdr-core/dns_monitor.py",
    "xdr-core/tls_fingerprint.py",
    "xdr-core/threat_intel.py",
    "xdr-core/ssl_probe.py",
    "xdr-core/forensic_collector.py",
    "ebpf-edr/edr.bpf.o",
]

# Check interval (seconds)
CHECK_INTERVAL = 120  # 2 minutes


def _sha256_file(path: str) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""


class SelfProtect:
    """XDR agent self-protection and anti-tampering."""

    def __init__(self, push_event_fn=None):
        self.push_event = push_event_fn
        self._stop = Event()
        self._thread = None
        self._lock = Lock()
        self._xdr_pid = os.getpid()

        # Hash database
        self._baseline_hashes = {}  # path -> sha256
        self._tamper_count = 0
        self._last_check = None

    def start(self):
        """Start self-protection monitoring."""
        self._baseline()
        self._thread = Thread(target=self._monitor_loop, daemon=True,
                            name="self-protect")
        self._thread.start()
        logger.info(f"Self-protection started (XDR PID={self._xdr_pid}, "
                   f"monitoring {len(self._baseline_hashes)} files)")

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    # ── Baseline ─────────────────────────────────────────

    def _baseline(self):
        """Create baseline hashes of critical files."""
        hashes = {}

        for rel_path in CRITICAL_FILES:
            full_path = str(XDR_DIR / rel_path)
            if os.path.isfile(full_path):
                h = _sha256_file(full_path)
                if h:
                    hashes[full_path] = h

        # Also hash all .py files in xdr-core/api/
        api_dir = XDR_DIR / "xdr-core" / "api"
        if api_dir.is_dir():
            for py_file in api_dir.glob("*.py"):
                h = _sha256_file(str(py_file))
                if h:
                    hashes[str(py_file)] = h

        with self._lock:
            self._baseline_hashes = hashes

        # Save baseline
        self._save_hashes()
        logger.info(f"Self-protect baseline: {len(hashes)} files hashed")

    def _save_hashes(self):
        """Save baseline hashes to disk."""
        try:
            with open(HASH_STORE, "w") as f:
                json.dump({
                    "created": datetime.now().isoformat(),
                    "xdr_pid": self._xdr_pid,
                    "hashes": self._baseline_hashes,
                }, f, indent=2)
        except Exception as e:
            logger.warning(f"Self-protect hash save error: {e}")

    # ── Integrity check ──────────────────────────────────

    def check_integrity(self) -> list[dict]:
        """Check all critical files against baseline."""
        alerts = []
        with self._lock:
            baseline = dict(self._baseline_hashes)

        for path, expected_hash in baseline.items():
            if not os.path.isfile(path):
                # File deleted!
                alerts.append({
                    "source": "DETECTOR",
                    "reason": "XDR_FILE_DELETED",
                    "mitre_id": "T1562.001",
                    "alert_level": 3,
                    "detail": (
                        f"XDR 자기보호: 핵심 파일 삭제 감지! "
                        f"{os.path.basename(path)}"
                    ),
                    "path": path,
                    "pid": 0,
                })
                continue

            current_hash = _sha256_file(path)
            if current_hash and current_hash != expected_hash:
                alerts.append({
                    "source": "DETECTOR",
                    "reason": "XDR_FILE_TAMPERED",
                    "mitre_id": "T1562.001",
                    "alert_level": 3,
                    "detail": (
                        f"XDR 자기보호: 파일 변조 감지! "
                        f"{os.path.basename(path)} "
                        f"(expected={expected_hash[:12]}... "
                        f"actual={current_hash[:12]}...)"
                    ),
                    "path": path,
                    "expected_hash": expected_hash,
                    "actual_hash": current_hash,
                    "pid": 0,
                })

        # Check XDR process is still running
        try:
            os.kill(self._xdr_pid, 0)
        except ProcessLookupError:
            alerts.append({
                "source": "DETECTOR",
                "reason": "XDR_PROCESS_KILLED",
                "mitre_id": "T1562.001",
                "alert_level": 3,
                "detail": f"XDR 자기보호: XDR 프로세스 종료 감지! PID={self._xdr_pid}",
                "pid": self._xdr_pid,
            })

        if alerts:
            with self._lock:
                self._tamper_count += len(alerts)

        return alerts

    # ── Monitor loop ─────────────────────────────────────

    def _monitor_loop(self):
        """Periodic integrity check loop + kernel security monitoring."""
        # Initial delay
        self._stop.wait(60)

        while not self._stop.is_set():
            try:
                alerts = self.check_integrity()
                self._last_check = datetime.now().isoformat()

                # Kernel security checks
                alerts.extend(self._check_kernel_security())

                for alert in alerts:
                    if self.push_event:
                        self.push_event(alert)
                    logger.warning(f"TAMPER ALERT: {alert['detail']}")

                    # Desktop notification for CRITICAL alerts
                    if alert.get("alert_level", 0) >= 3:
                        try:
                            from desktop_notify import send_xdr_alert
                            send_xdr_alert(
                                alert.get("reason", "SECURITY_ALERT"),
                                alert["detail"],
                                alert_level=alert["alert_level"]
                            )
                        except Exception:
                            pass

            except Exception as e:
                logger.debug(f"Self-protect check error: {e}")

            self._stop.wait(CHECK_INTERVAL)

    def _check_kernel_security(self) -> list[dict]:
        """Check kernel lockdown and sysctl security settings."""
        alerts = []
        import subprocess

        # 1. Check lockdown status
        try:
            lockdown = Path("/sys/kernel/security/lockdown").read_text().strip()
            if "[none]" in lockdown:
                alerts.append({
                    "type": "KERNEL_SECURITY", "source": "SELF_PROTECT",
                    "alert_level": 3,  # CRITICAL
                    "reason": "LOCKDOWN_DISABLED",
                    "detail": f"Kernel lockdown is DISABLED: {lockdown}",
                    "mitre_tactic": "Defense Evasion",
                    "mitre_technique": "T1562.001",
                })
                # Attempt auto-remediation
                try:
                    Path("/sys/kernel/security/lockdown").write_text("integrity")
                    logger.info("Auto-remediation: lockdown re-enabled")
                except (PermissionError, OSError):
                    pass
        except (FileNotFoundError, PermissionError):
            pass

        # 2. Check unprivileged_bpf_disabled
        try:
            val = Path("/proc/sys/kernel/unprivileged_bpf_disabled").read_text().strip()
            if val == "0":
                alerts.append({
                    "type": "KERNEL_SECURITY", "source": "SELF_PROTECT",
                    "alert_level": 3,  # CRITICAL
                    "reason": "BPF_UNRESTRICTED",
                    "detail": "unprivileged_bpf_disabled=0: any user can load eBPF",
                    "mitre_tactic": "Defense Evasion",
                    "mitre_technique": "T1562.001",
                })
                # Attempt auto-remediation
                try:
                    subprocess.run(
                        ["sysctl", "-w", "kernel.unprivileged_bpf_disabled=2"],
                        capture_output=True, timeout=5
                    )
                    logger.info("Auto-remediation: unprivileged_bpf_disabled set to 2")
                except Exception:
                    pass
        except (FileNotFoundError, PermissionError):
            pass

        # 3. Check kexec
        try:
            val = Path("/proc/sys/kernel/kexec_load_disabled").read_text().strip()
            if val == "0":
                alerts.append({
                    "type": "KERNEL_SECURITY", "source": "SELF_PROTECT",
                    "alert_level": 2,  # WARNING
                    "reason": "KEXEC_ENABLED",
                    "detail": "kexec_load_disabled=0: kernel can be replaced at runtime",
                    "mitre_tactic": "Defense Evasion",
                    "mitre_technique": "T1601",
                })
        except (FileNotFoundError, PermissionError):
            pass

        return alerts

    # ── Update baseline (after legitimate deploy) ────────

    def update_baseline(self):
        """Re-baseline after legitimate file update (deploy)."""
        self._baseline()
        logger.info("Self-protect: baseline updated after deploy")
        return {"status": "ok", "files": len(self._baseline_hashes)}

    # ── API helpers ──────────────────────────────────────

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "xdr_pid": self._xdr_pid,
                "monitored_files": len(self._baseline_hashes),
                "tamper_alerts": self._tamper_count,
                "last_check": self._last_check,
            }
