#!/usr/bin/env python3
"""
XDR BPF Guard — Loader and Manager.

Loads the BPF LSM guard program that restricts bpf() syscall access
to XDR processes only. Manages the allowed PID whitelist and monitors
denied access attempts.

Usage:
    guard = BPFGuard()
    guard.load()                    # Load guard program
    guard.register_pid(os.getpid()) # Register XDR PID
    guard.enable()                  # Start enforcing
    guard.monitor_denied()          # Watch for denied attempts
"""

import os
import sys
import time
import ctypes
import struct
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger("xdr.bpf_guard")

# Guard BPF object path
GUARD_OBJ = Path(__file__).parent.parent / "ebpf-edr" / "bpf_guard.bpf.o"
GUARD_OBJ_INSTALLED = Path("/opt/xdr/xdr-core/bpf_guard.bpf.o")

# BPF map pin paths
BPF_FS = Path("/sys/fs/bpf")
PIN_DIR = BPF_FS / "xdr_guard"


class BPFGuard:
    """Manages the BPF LSM guard that restricts eBPF access."""

    def __init__(self):
        self._loaded = False
        self._enforcing = False

    def load(self) -> bool:
        """Load the BPF guard LSM program via bpftool.

        Returns True if successfully loaded or already loaded.
        """
        if self._loaded:
            return True

        # Find the guard object
        obj_path = GUARD_OBJ_INSTALLED if GUARD_OBJ_INSTALLED.exists() else GUARD_OBJ
        if not obj_path.exists():
            logger.error(f"BPF Guard object not found: {obj_path}")
            return False

        try:
            # Create pin directory
            PIN_DIR.mkdir(parents=True, exist_ok=True)

            # Load all programs from the object file
            result = subprocess.run(
                ["bpftool", "prog", "loadall", str(obj_path), str(PIN_DIR),
                 "type", "lsm"],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                logger.error(f"Failed to load BPF Guard: {result.stderr}")
                return False

            # Attach LSM programs
            for prog_name in ["guard_bpf", "guard_bpf_map", "guard_bpf_prog"]:
                pin_path = PIN_DIR / prog_name
                if pin_path.exists():
                    attach_result = subprocess.run(
                        ["bpftool", "prog", "attach", "pinned",
                         str(pin_path), "lsm"],
                        capture_output=True, text=True, timeout=10
                    )
                    if attach_result.returncode != 0:
                        logger.warning(
                            f"Failed to attach {prog_name}: {attach_result.stderr}"
                        )

            self._loaded = True
            logger.info("BPF Guard loaded successfully")
            return True

        except subprocess.TimeoutExpired:
            logger.error("BPF Guard load timed out")
            return False
        except Exception as e:
            logger.error(f"BPF Guard load error: {e}")
            return False

    def register_pid(self, pid: int) -> bool:
        """Register a PID as allowed to use bpf().

        Should be called with the XDR engine's PID before enabling enforcement.
        """
        try:
            # Find the map fd via bpftool
            result = subprocess.run(
                ["bpftool", "map", "show", "pinned",
                 str(PIN_DIR / "xdr_allowed_pids")],
                capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                # Update map: key=pid, value=1 (allowed)
                key_hex = struct.pack("<I", pid).hex()
                val_hex = struct.pack("<I", 1).hex()

                update_result = subprocess.run(
                    ["bpftool", "map", "update", "pinned",
                     str(PIN_DIR / "xdr_allowed_pids"),
                     "key", "hex"] + list(key_hex) + [
                     "value", "hex"] + list(val_hex),
                    capture_output=True, text=True, timeout=5
                )

                if update_result.returncode == 0:
                    logger.info(f"BPF Guard: registered PID {pid} as allowed")
                    return True
                else:
                    logger.error(
                        f"Failed to register PID {pid}: {update_result.stderr}"
                    )

            # Fallback: use bpftool map update with different syntax
            update_result = subprocess.run(
                ["bpftool", "map", "update", "pinned",
                 str(PIN_DIR / "xdr_allowed_pids"),
                 "key", str(pid), "0", "0", "0",
                 "value", "1", "0", "0", "0"],
                capture_output=True, text=True, timeout=5
            )

            if update_result.returncode == 0:
                logger.info(f"BPF Guard: registered PID {pid} as allowed")
                return True

            logger.error(f"Failed to register PID: {update_result.stderr}")
            return False

        except Exception as e:
            logger.error(f"BPF Guard register error: {e}")
            return False

    def enable(self) -> bool:
        """Enable enforcement — start blocking non-XDR bpf() calls."""
        try:
            result = subprocess.run(
                ["bpftool", "map", "update", "pinned",
                 str(PIN_DIR / "guard_config"),
                 "key", "0", "0", "0", "0",
                 "value", "1", "0", "0", "0"],
                capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                self._enforcing = True
                logger.info("BPF Guard: enforcement ENABLED")
                return True

            logger.error(f"Failed to enable guard: {result.stderr}")
            return False

        except Exception as e:
            logger.error(f"BPF Guard enable error: {e}")
            return False

    def disable(self) -> bool:
        """Disable enforcement — allow all bpf() calls."""
        try:
            result = subprocess.run(
                ["bpftool", "map", "update", "pinned",
                 str(PIN_DIR / "guard_config"),
                 "key", "0", "0", "0", "0",
                 "value", "0", "0", "0", "0"],
                capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                self._enforcing = False
                logger.info("BPF Guard: enforcement DISABLED")
                return True

            return False

        except Exception as e:
            logger.error(f"BPF Guard disable error: {e}")
            return False

    def get_stats(self) -> dict:
        """Get guard statistics (allowed/denied counts)."""
        stats = {"allowed": 0, "denied": 0}
        try:
            result = subprocess.run(
                ["bpftool", "map", "dump", "pinned",
                 str(PIN_DIR / "guard_stats")],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Parse bpftool output
                lines = result.stdout.strip()
                logger.debug(f"Guard stats raw: {lines}")
        except Exception:
            pass
        return stats

    def unload(self):
        """Unload the guard program and clean up pins."""
        try:
            # Remove pin directory
            if PIN_DIR.exists():
                subprocess.run(
                    ["rm", "-rf", str(PIN_DIR)],
                    capture_output=True, timeout=5
                )
            self._loaded = False
            self._enforcing = False
            logger.info("BPF Guard unloaded")
        except Exception as e:
            logger.error(f"BPF Guard unload error: {e}")

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def is_enforcing(self) -> bool:
        return self._enforcing
