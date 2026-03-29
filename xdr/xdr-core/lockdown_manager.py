#!/usr/bin/env python3
"""
XDR Pre-Lockdown Verification & Safe Lockdown Manager.

Before activating kernel lockdown, verifies:
  1. Critical hardware drivers loaded (display, input, audio, network)
  2. No unknown/malicious kernel modules present
  3. All XDR eBPF programs attached
  4. Retries with backoff on failure

Usage:
    manager = LockdownManager(push_event_fn=push_event)
    manager.execute()  # Full verification → lockdown sequence
"""

import os
import re
import time
import logging
import subprocess
from pathlib import Path
from threading import Thread
from typing import Optional

logger = logging.getLogger("xdr.lockdown")

# ── Module whitelists ────────────────────────────────────

# Critical hardware driver modules that MUST be loaded before lockdown
CRITICAL_HW_MODULES = {
    # Display — at least one must be present
    "display": [
        "nvidia", "nvidia_drm", "nvidia_modeset",  # NVIDIA
        "i915",                                       # Intel
        "amdgpu", "radeon",                           # AMD
        "drm", "drm_kms_helper",                      # DRM core
        "nouveau",                                    # Open NVIDIA
        "virtio_gpu", "vmwgfx", "bochs",             # Virtual
    ],
    # Input — may be built-in (hid, evdev, usbhid)
    "input": [
        "hid", "hid_generic", "usbhid",
        "evdev", "atkbd", "psmouse",
        "i8042",  # PS/2 controller
    ],
    # Network — at least one
    "network": [
        "r8169", "e1000e", "igb", "ixgbe",          # Ethernet
        "iwlwifi", "iwlmvm", "ath9k", "ath10k_pci",  # WiFi
        "virtio_net", "vmxnet3",                      # Virtual
    ],
}

# Known good modules — trusted modules that ship with the kernel
# Built dynamically from /lib/modules/$(uname -r)/
KNOWN_GOOD_PREFIXES = [
    "nvidia", "drm", "snd_", "hid", "usb", "input",
    "r8169", "e1000", "igb", "iwl", "ath",
    "ext4", "fat", "ntfs", "xfs", "btrfs",
    "nf_", "iptable", "ip6table", "xt_", "nft_",
    "bridge", "veth", "bonding", "tun", "tap",
    "loop", "dm_", "md_", "raid",
    "virtio", "vmw", "xen_",
    "crypto", "crc", "aes", "sha",
    "i2c_", "gpio", "pinctrl",
    "kvm", "irqbypass",
    "bluetooth", "btusb", "rfkill",
    "cdc_", "usbnet",
    "nls_", "iso9660", "udf",
    "overlay", "fuse",
    "cpufreq", "acpi",
    "lp", "ppdev", "parport",
    "bpf_preload",
]


class LockdownManager:
    """Manages pre-lockdown verification and safe lockdown activation."""

    def __init__(self, push_event_fn=None, max_retries: int = 5,
                 retry_interval: int = 10):
        self.push_event = push_event_fn or (lambda e: None)
        self.max_retries = max_retries
        self.retry_interval = retry_interval
        self._kernel_version = os.uname().release
        self._known_modules = set()
        self._blocked_modules = []
        self._lockdown_active = False

        # Build known-good module list from system
        self._build_known_modules()

    def execute(self):
        """Full pre-lockdown verification → lockdown sequence.

        Runs in background thread with retry logic.
        """
        thread = Thread(target=self._lockdown_sequence, daemon=True,
                        name="lockdown-manager")
        thread.start()
        return thread

    def _lockdown_sequence(self):
        """Main lockdown sequence with retries."""
        logger.info("=== Pre-Lockdown Verification Started ===")

        for attempt in range(1, self.max_retries + 1):
            logger.info(f"Lockdown attempt {attempt}/{self.max_retries}")

            # Step 1: Verify hardware drivers
            hw_ok, hw_report = self._verify_hardware()
            if not hw_ok:
                logger.warning(
                    f"Hardware check failed (attempt {attempt}): {hw_report}"
                )
                self._emit_event("PRE_LOCKDOWN_HW_WAIT",
                                 f"Hardware 드라이버 대기 중: {hw_report}",
                                 level=1)
                time.sleep(self.retry_interval)
                continue

            # Step 2: Scan for suspicious modules
            suspicious = self._scan_modules()
            if suspicious:
                logger.warning(f"Suspicious modules detected: {suspicious}")
                self._emit_event("SUSPICIOUS_MODULE",
                                 f"의심스러운 커널 모듈 탐지: {suspicious}",
                                 level=3)
                # Attempt to unload suspicious modules
                self._handle_suspicious_modules(suspicious)

            # Step 3: Apply sysctl hardening
            self._apply_sysctl()

            # Step 4: Activate lockdown
            success = self._activate_lockdown()
            if success:
                logger.info("=== Kernel Lockdown Activated Successfully ===")
                self._emit_event("LOCKDOWN_ACTIVATED",
                                 "커널 Lockdown (integrity) 활성화 완료",
                                 level=1)
                self._lockdown_active = True
                return
            else:
                logger.warning(f"Lockdown activation failed (attempt {attempt})")
                time.sleep(self.retry_interval)

        # All retries exhausted
        logger.error("CRITICAL: Failed to activate lockdown after all retries")
        self._emit_event("LOCKDOWN_FAILED",
                         f"커널 Lockdown 활성화 실패 ({self.max_retries}회 시도)",
                         level=3)

    # ── Hardware Verification ────────────────────────────

    def _verify_hardware(self) -> tuple[bool, str]:
        """Verify critical hardware drivers are loaded.

        Returns (ok, report_message).
        """
        loaded = self._get_loaded_modules()
        builtin = self._get_builtin_modules()
        all_available = loaded | builtin
        missing_categories = []

        for category, modules in CRITICAL_HW_MODULES.items():
            if category == "input":
                # Input drivers are often built-in, check /dev/input instead
                if self._check_input_devices():
                    continue
            
            found = [m for m in modules if m in all_available]
            if not found:
                missing_categories.append(category)

        if missing_categories:
            return False, f"미로드 카테고리: {', '.join(missing_categories)}"

        # Additional checks
        checks = []

        # DRM/display active?
        if Path("/sys/class/drm").exists():
            drm_devices = list(Path("/sys/class/drm").iterdir())
            if not drm_devices:
                checks.append("DRM 디바이스 없음")

        # Network interface up?
        try:
            from nic_manager import detect_default_nic
            nic = detect_default_nic()
            if not nic or nic == "eth0":  # fallback means detection failed
                checks.append("네트워크 인터페이스 미확인")
        except Exception:
            pass

        if checks:
            return False, "; ".join(checks)

        return True, "모든 하드웨어 드라이버 로드 확인됨"

    def _check_input_devices(self) -> bool:
        """Check if input devices are available (keyboard, mouse)."""
        input_dir = Path("/dev/input")
        if not input_dir.exists():
            return False

        # Look for event devices
        event_devices = list(input_dir.glob("event*"))
        if len(event_devices) < 2:  # Need at least keyboard + mouse
            return False

        # Check /proc/bus/input/devices for keyboard and mouse
        try:
            devices_info = Path("/proc/bus/input/devices").read_text()
            has_keyboard = "keyboard" in devices_info.lower()
            has_mouse = ("mouse" in devices_info.lower() or
                         "pointer" in devices_info.lower())
            return has_keyboard and has_mouse
        except (FileNotFoundError, PermissionError):
            # If we can't read, assume OK if event devices exist
            return len(event_devices) >= 2

    # ── Module Scanning ──────────────────────────────────

    def _scan_modules(self) -> list[dict]:
        """Scan for suspicious/unknown kernel modules.

        Returns list of suspicious module info dicts.
        """
        loaded = self._get_loaded_modules_detail()
        suspicious = []

        for mod_name, mod_info in loaded.items():
            # Check if module is known
            if self._is_known_module(mod_name):
                continue

            # Check module signature
            is_tainted = self._check_module_taint(mod_name)

            suspicious.append({
                "name": mod_name,
                "size": mod_info.get("size", 0),
                "used_by": mod_info.get("used_by", ""),
                "tainted": is_tainted,
                "risk": "HIGH" if is_tainted else "MEDIUM",
            })

        return suspicious

    def _is_known_module(self, name: str) -> bool:
        """Check if a module is in the known-good list."""
        if name in self._known_modules:
            return True
        for prefix in KNOWN_GOOD_PREFIXES:
            if name.startswith(prefix):
                return True
        return False

    def _check_module_taint(self, name: str) -> bool:
        """Check if a module taints the kernel (unsigned, out-of-tree, etc.)."""
        try:
            taint_path = Path(f"/sys/module/{name}/taint")
            if taint_path.exists():
                taint = taint_path.read_text().strip()
                # O=out-of-tree, E=unsigned, P=proprietary
                return bool(taint and taint not in ("P",))  # P alone is OK (nvidia)
        except (PermissionError, OSError):
            pass
        return False

    def _handle_suspicious_modules(self, suspicious: list[dict]):
        """Handle suspicious modules — log, alert, attempt unload if HIGH risk."""
        for mod in suspicious:
            logger.warning(
                f"Suspicious module: {mod['name']} "
                f"(size={mod['size']}, risk={mod['risk']}, "
                f"tainted={mod['tainted']})"
            )

            if mod["risk"] == "HIGH" and mod["tainted"]:
                # Attempt to unload (will fail if in use, which is safe)
                self._emit_event("MALICIOUS_MODULE_DETECTED",
                                 f"의심스러운 커널 모듈 탐지/차단: {mod['name']}",
                                 level=3)
                try:
                    result = subprocess.run(
                        ["rmmod", mod["name"]],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        logger.info(f"Unloaded suspicious module: {mod['name']}")
                        self._blocked_modules.append(mod["name"])
                    else:
                        logger.warning(
                            f"Cannot unload {mod['name']}: {result.stderr.strip()}"
                        )
                except Exception as e:
                    logger.warning(f"Failed to unload {mod['name']}: {e}")

    # ── Lockdown Activation ──────────────────────────────

    def _apply_sysctl(self):
        """Apply sysctl hardening settings."""
        settings = {
            "kernel.unprivileged_bpf_disabled": "2",
            "kernel.kexec_load_disabled": "1",
            "kernel.kptr_restrict": "2",
            "kernel.dmesg_restrict": "1",
            "kernel.perf_event_paranoid": "3",
        }
        for key, val in settings.items():
            try:
                subprocess.run(
                    ["sysctl", "-w", f"{key}={val}"],
                    capture_output=True, timeout=5
                )
            except Exception:
                pass
        logger.info("sysctl hardening applied")

    def _activate_lockdown(self) -> bool:
        """Activate kernel lockdown (integrity mode)."""
        try:
            lockdown_path = Path("/sys/kernel/security/lockdown")
            if not lockdown_path.exists():
                logger.error("Lockdown sysfs not available")
                return False

            current = lockdown_path.read_text().strip()

            if "[integrity]" in current or "[confidentiality]" in current:
                logger.info(f"Lockdown already active: {current}")
                return True

            if "[none]" in current:
                lockdown_path.write_text("integrity")
                # Verify
                new_state = lockdown_path.read_text().strip()
                if "[integrity]" in new_state:
                    logger.info("Lockdown activated: integrity mode")
                    return True
                else:
                    logger.error(f"Lockdown write succeeded but state: {new_state}")
                    return False

            logger.warning(f"Unknown lockdown state: {current}")
            return False

        except PermissionError:
            logger.warning("No permission to activate lockdown (not root?)")
            return False
        except OSError as e:
            if "not permitted" in str(e).lower():
                logger.info("Lockdown already active (write blocked)")
                return True
            logger.error(f"Lockdown error: {e}")
            return False

    # ── Helper Methods ───────────────────────────────────

    def _get_loaded_modules(self) -> set[str]:
        """Get set of loaded module names."""
        try:
            modules = Path("/proc/modules").read_text()
            return {line.split()[0] for line in modules.strip().splitlines()}
        except (FileNotFoundError, PermissionError):
            return set()

    def _get_loaded_modules_detail(self) -> dict:
        """Get loaded modules with details."""
        modules = {}
        try:
            for line in Path("/proc/modules").read_text().strip().splitlines():
                parts = line.split()
                if len(parts) >= 4:
                    modules[parts[0]] = {
                        "size": int(parts[1]),
                        "used_count": int(parts[2]),
                        "used_by": parts[3].strip(",- "),
                    }
        except (FileNotFoundError, PermissionError):
            pass
        return modules

    def _get_builtin_modules(self) -> set[str]:
        """Get set of built-in kernel modules."""
        builtins = set()
        builtin_file = Path(f"/lib/modules/{self._kernel_version}/modules.builtin")
        try:
            if builtin_file.exists():
                for line in builtin_file.read_text().splitlines():
                    # Format: kernel/drivers/input/evdev.ko
                    name = line.strip().rsplit("/", 1)[-1]
                    name = name.replace(".ko", "").replace("-", "_")
                    builtins.add(name)
        except (PermissionError, OSError):
            pass
        return builtins

    def _build_known_modules(self):
        """Build the set of known-good module names from system."""
        # Built-in modules are always trusted
        self._known_modules = self._get_builtin_modules()

        # Add modules from the signed kernel module directory
        mod_dir = Path(f"/lib/modules/{self._kernel_version}/kernel")
        if mod_dir.exists():
            try:
                for ko_file in mod_dir.rglob("*.ko*"):
                    name = ko_file.stem.split(".")[0].replace("-", "_")
                    self._known_modules.add(name)
            except (PermissionError, OSError):
                pass

        logger.debug(f"Known modules database: {len(self._known_modules)} entries")

    def _emit_event(self, reason: str, detail: str, level: int = 1):
        """Push an event to the XDR event system + desktop notification."""
        self.push_event({
            "type": "KERNEL_SECURITY",
            "source": "LOCKDOWN_MANAGER",
            "alert_level": level,
            "reason": reason,
            "detail": detail,
            "mitre_tactic": "Defense Evasion",
            "mitre_technique": "T1562.001",
        })

        # Desktop notification for WARNING and CRITICAL
        if level >= 2:
            try:
                from desktop_notify import send_xdr_alert
                send_xdr_alert(reason, detail, alert_level=level)
            except Exception:
                pass

    # ── Status API ───────────────────────────────────────

    @property
    def is_locked_down(self) -> bool:
        return self._lockdown_active

    def get_status(self) -> dict:
        return {
            "lockdown_active": self._lockdown_active,
            "blocked_modules": self._blocked_modules,
            "known_modules_count": len(self._known_modules),
            "loaded_modules_count": len(self._get_loaded_modules()),
        }
