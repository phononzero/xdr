#!/usr/bin/env python3
"""
XDR Asset Scanner — Periodic security analysis of system assets.

Scans loaded and installed assets (modules, packages, hardware) and
classifies them as SAFE, SUSPICIOUS, MALICIOUS, or UNKNOWN.
"""

import os
import time
import logging
import subprocess
from pathlib import Path
from threading import Thread, Event
from datetime import datetime

from asset_manager import get_loaded_modules, get_installed_packages, get_hardware_devices
from asset_policy import get_policy
from asset_logger import get_logger, EVT_SCAN_RESULT

logger = logging.getLogger("xdr.scanner")

# Safety classifications
SAFE = "safe"
SUSPICIOUS = "suspicious"
MALICIOUS = "malicious"
UNKNOWN = "unknown"

# Scan interval (seconds)
DEFAULT_INTERVAL = 300  # 5 minutes


class AssetScanner:
    """Background scanner for system asset security analysis."""

    def __init__(self, push_event_fn=None, interval: int = DEFAULT_INTERVAL):
        self.push_event = push_event_fn or (lambda e: None)
        self.interval = interval
        self._stop = Event()
        self._last_scan = None
        self._last_results = {}
        self._thread = None

    def start(self):
        """Start periodic scanning in background."""
        self._thread = Thread(target=self._scan_loop, daemon=True,
                              name="asset-scanner")
        self._thread.start()
        logger.info(f"Asset scanner started (interval={self.interval}s)")

    def stop(self):
        self._stop.set()

    def scan_now(self) -> dict:
        """Run a scan immediately and return results."""
        return self._run_scan()

    def get_last_results(self) -> dict:
        return self._last_results

    def _scan_loop(self):
        # Initial delay
        self._stop.wait(30)

        while not self._stop.is_set():
            try:
                self._run_scan()
            except Exception as e:
                logger.error(f"Scan error: {e}")
            self._stop.wait(self.interval)

    def _run_scan(self) -> dict:
        """Execute full scan: modules, packages, hardware."""
        start_time = time.time()
        policy = get_policy()
        asset_log = get_logger()

        results = {
            "timestamp": datetime.now().isoformat(),
            "modules": self._scan_modules(policy),
            "packages": self._scan_packages(policy),
            "hardware": self._scan_hardware(policy),
            "summary": {},
        }

        # Build summary
        for category in ("modules", "packages", "hardware"):
            items = results[category]
            results["summary"][category] = {
                "total": len(items),
                "safe": sum(1 for i in items if i["verdict"] == SAFE),
                "suspicious": sum(1 for i in items if i["verdict"] == SUSPICIOUS),
                "malicious": sum(1 for i in items if i["verdict"] == MALICIOUS),
                "unknown": sum(1 for i in items if i["verdict"] == UNKNOWN),
            }

        results["duration_ms"] = int((time.time() - start_time) * 1000)
        self._last_scan = datetime.now().isoformat()
        self._last_results = results

        # Log results
        total_suspicious = sum(
            results["summary"][c]["suspicious"] + results["summary"][c]["malicious"]
            for c in ("modules", "packages", "hardware")
        )

        asset_log.log(
            EVT_SCAN_RESULT, "system", "full_scan",
            detail=f"스캔 완료: {total_suspicious}개 위험 항목",
            result="warning" if total_suspicious > 0 else "clean",
            extra={"summary": results["summary"]}
        )

        # Alert if malicious found
        if total_suspicious > 0:
            self.push_event({
                "type": "ASSET_SCAN", "source": "SCANNER",
                "alert_level": 3 if any(
                    results["summary"][c]["malicious"] > 0
                    for c in ("modules", "packages", "hardware")
                ) else 2,
                "detail": f"자산 스캔: {total_suspicious}개 의심/악성 항목 탐지",
            })

            try:
                from desktop_notify import send_xdr_alert
                send_xdr_alert(
                    "ASSET_SCAN",
                    f"보안 스캔: {total_suspicious}개 의심/악성 항목 탐지",
                    alert_level=3
                )
            except Exception:
                pass

        return results

    def _scan_modules(self, policy) -> list[dict]:
        """Scan loaded kernel modules."""
        results = []
        modules = get_loaded_modules()

        for mod in modules:
            name = mod["name"]
            verdict = UNKNOWN
            reason = ""

            if policy.is_blacklisted("modules", name):
                verdict = MALICIOUS
                reason = "블랙리스트에 등록된 모듈"
            elif policy.is_whitelisted("modules", name):
                verdict = SAFE
                reason = "화이트리스트 등록 모듈"
            elif mod.get("safety") == "safe":
                verdict = SAFE
                reason = "시스템 커널 모듈"
            elif mod.get("taint") and mod["taint"] not in ("P",):
                verdict = SUSPICIOUS
                reason = f"커널 오염 플래그: {mod['taint']}"
            elif mod.get("is_builtin"):
                verdict = SAFE
                reason = "커널 내장 모듈"

            results.append({
                "name": name,
                "category": "modules",
                "verdict": verdict,
                "reason": reason,
                "details": {
                    "size_kb": mod.get("size_kb", 0),
                    "taint": mod.get("taint", ""),
                    "used_count": mod.get("used_count", 0),
                },
            })

        return results

    def _scan_packages(self, policy) -> list[dict]:
        """Scan installed packages."""
        results = []
        # Only scan running packages for performance
        packages = get_installed_packages()

        for pkg in packages[:500]:  # Limit for performance
            name = pkg["name"]
            verdict = UNKNOWN
            reason = ""

            if policy.is_blacklisted("packages", name):
                verdict = MALICIOUS
                reason = "블랙리스트에 등록된 패키지"
            elif policy.is_whitelisted("packages", name):
                verdict = SAFE
                reason = "화이트리스트 등록 패키지"
            elif pkg.get("running"):
                verdict = SAFE
                reason = "실행 중인 시스템 패키지"
            else:
                verdict = SAFE
                reason = "설치된 패키지"

            results.append({
                "name": name,
                "category": "packages",
                "verdict": verdict,
                "reason": reason,
                "details": {
                    "version": pkg.get("version", ""),
                    "running": pkg.get("running", False),
                },
            })

        return results

    def _scan_hardware(self, policy) -> list[dict]:
        """Scan connected hardware."""
        results = []
        devices = get_hardware_devices()

        for dev in devices:
            name = dev.get("name", "unknown")
            dev_id = f"{dev.get('vendor_id', '')}:{dev.get('product_id', '')}"
            verdict = UNKNOWN
            reason = ""

            if policy.is_blacklisted("hardware", name) or \
               policy.is_blacklisted("hardware", dev_id):
                verdict = MALICIOUS
                reason = "블랙리스트에 등록된 디바이스"
            elif policy.is_whitelisted("hardware", name) or \
                 policy.is_whitelisted("hardware", dev_id):
                verdict = SAFE
                reason = "화이트리스트 등록 디바이스"
            elif dev.get("type") == "input":
                verdict = SAFE
                reason = "입력 디바이스"
            elif dev.get("type") == "pci":
                verdict = SAFE
                reason = "PCI 디바이스"
            else:
                verdict = UNKNOWN
                reason = "미분류 디바이스"

            results.append({
                "name": name,
                "category": "hardware",
                "verdict": verdict,
                "reason": reason,
                "details": dev,
            })

        return results
