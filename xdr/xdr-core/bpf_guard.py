#!/usr/bin/env python3
"""
XDR BPF Guard — Loader and Manager.

Loads the BPF LSM guard program that restricts bpf() syscall access
to XDR processes only. Manages the allowed PID whitelist and monitors
denied access attempts.

Usage:
    guard = BPFGuard()
    guard.load()                    # Load + auto-attach, pin maps
    guard.register_pid(os.getpid()) # Register XDR PID
    guard.enable()                  # Start enforcing
    guard.get_stats()               # {"allowed": N, "denied": M, "enforcing": bool}
    guard.get_denied_events()       # Drain recent denied bpf() attempts
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

# bpf() syscall (x86_64) for in-process map reads. Reading via in-process bpf()
# (rather than a bpftool subprocess) is essential: once the guard is ENFORCING,
# a bpftool child is a different PID and gets denied — but the registered XDR
# process itself is allowed, so it can still read guard_stats directly.
_SYS_BPF = 321
_BPF_MAP_LOOKUP_ELEM = 1
_BPF_OBJ_GET = 7


class _BpfObjGetAttr(ctypes.Structure):
    _fields_ = [("pathname", ctypes.c_uint64),
                ("bpf_fd", ctypes.c_uint32),
                ("file_flags", ctypes.c_uint32)]


class _BpfLookupAttr(ctypes.Structure):
    _fields_ = [("map_fd", ctypes.c_uint32),
                ("_pad", ctypes.c_uint32),
                ("key", ctypes.c_uint64),
                ("value", ctypes.c_uint64),
                ("flags", ctypes.c_uint64)]


def _bpf_obj_get(pin_path: str) -> int:
    """bpf(BPF_OBJ_GET) — open a pinned map/prog, return fd or -1."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    buf = ctypes.create_string_buffer(pin_path.encode() + b"\x00")
    attr = _BpfObjGetAttr(pathname=ctypes.addressof(buf))
    fd = libc.syscall(_SYS_BPF, _BPF_OBJ_GET, ctypes.byref(attr),
                      ctypes.sizeof(attr))
    return fd


def _map_lookup_u64(map_fd: int, index: int) -> int | None:
    """bpf(BPF_MAP_LOOKUP_ELEM) on a u32-key / u64-value array map."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    key = ctypes.c_uint32(index)
    val = ctypes.c_uint64(0)
    attr = _BpfLookupAttr(map_fd=map_fd, key=ctypes.addressof(key),
                          value=ctypes.addressof(val))
    rc = libc.syscall(_SYS_BPF, _BPF_MAP_LOOKUP_ELEM, ctypes.byref(attr),
                      ctypes.sizeof(attr))
    return val.value if rc == 0 else None


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
            # Clean any stale pins from a previous run
            if PIN_DIR.exists():
                subprocess.run(["rm", "-rf", str(PIN_DIR)],
                               capture_output=True, timeout=5)
            PIN_DIR.mkdir(parents=True, exist_ok=True)

            # Load + auto-attach the LSM programs AND pin the maps.
            #   - autoattach: LSM programs must be attached via the kernel LSM
            #     mechanism at load time; `bpftool prog attach ... lsm` is not a
            #     valid attach type and always fails.
            #   - pinmaps: pins guard_stats / guard_config / xdr_allowed_pids /
            #     denied_events into PIN_DIR so register_pid/enable/get_stats
            #     can reach them (loadall alone pins only programs).
            result = subprocess.run(
                ["bpftool", "prog", "loadall", str(obj_path), str(PIN_DIR),
                 "autoattach", "pinmaps", str(PIN_DIR)],
                capture_output=True, text=True, timeout=15
            )

            if result.returncode != 0:
                logger.error(f"Failed to load BPF Guard: {result.stderr}")
                return False

            self._loaded = True
            logger.info("BPF Guard loaded + attached (autoattach), maps pinned")
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
        map_path = str(PIN_DIR / "xdr_allowed_pids")
        # key = pid (u32 LE), value = 1 (u32 LE) → one hex token PER BYTE.
        # (The old code did list(hexstring) which splits into nibble chars and
        # bpftool rejects it.)
        key_tokens = [f"{b:02x}" for b in struct.pack("<I", pid)]
        val_tokens = [f"{b:02x}" for b in struct.pack("<I", 1)]
        try:
            update_result = subprocess.run(
                ["bpftool", "map", "update", "pinned", map_path,
                 "key", "hex", *key_tokens,
                 "value", "hex", *val_tokens],
                capture_output=True, text=True, timeout=5
            )
            if update_result.returncode == 0:
                logger.info(f"BPF Guard: registered PID {pid} as allowed")
                return True
            logger.error(f"Failed to register PID {pid}: {update_result.stderr}")
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
        """Get guard statistics (allowed/denied counts).

        guard_stats is an ARRAY map of 2x __u64: index0=allowed, index1=denied.
        """
        stats = {"allowed": 0, "denied": 0, "enforcing": self._enforcing}

        # Primary: in-process bpf() read of the pinned array map. Works even
        # while enforcing (this process is registered/allowed).
        try:
            fd = _bpf_obj_get(str(PIN_DIR / "guard_stats"))
            if fd >= 0:
                a = _map_lookup_u64(fd, 0)
                d = _map_lookup_u64(fd, 1)
                os.close(fd)
                if a is not None or d is not None:
                    stats["allowed"] = int(a or 0)
                    stats["denied"] = int(d or 0)
                    return stats
        except Exception as e:
            logger.debug(f"Guard stats in-process read failed: {e}")

        # Fallback: bpftool JSON dump (only works when NOT enforcing).
        try:
            import json
            result = subprocess.run(
                ["bpftool", "-j", "map", "dump", "pinned",
                 str(PIN_DIR / "guard_stats")],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return stats
            for e in json.loads(result.stdout):
                fmt = e.get("formatted")
                if fmt is not None:
                    idx, val = fmt.get("key"), fmt.get("value")
                else:
                    kb = [int(x, 16) for x in e.get("key", [])]
                    vb = [int(x, 16) for x in e.get("value", [])]
                    idx = kb[0] if kb else None
                    val = int.from_bytes(bytes(vb), "little") if vb else 0
                if idx == 0:
                    stats["allowed"] = int(val)
                elif idx == 1:
                    stats["denied"] = int(val)
        except Exception as e:
            logger.debug(f"Guard stats parse error: {e}")
        return stats

    def get_denied_events(self, max_events: int = 64) -> list[dict]:
        """Drain recent denied-bpf() attempts from the denied_events ring buffer.

        Best-effort snapshot (consumes the ring buffer). Each entry:
        {pid, uid, bpf_cmd, comm}. Returns [] if libbpf/map is unavailable.
        """
        events: list[dict] = []
        try:
            from engine.ring_buffer import RingBufferPoller
        except Exception:
            return events

        class _DeniedEvent(ctypes.Structure):
            _fields_ = [
                ("pid", ctypes.c_uint32),
                ("uid", ctypes.c_uint32),
                ("bpf_cmd", ctypes.c_uint32),
                ("comm", ctypes.c_char * 16),
            ]

        # Open the pinned ring buffer in-process (allowed under enforcement).
        fd = _bpf_obj_get(str(PIN_DIR / "denied_events"))
        if fd < 0:
            return events

        def _cb(ctx, data, size):
            if size < ctypes.sizeof(_DeniedEvent) or len(events) >= max_events:
                return 0
            ev = _DeniedEvent.from_buffer_copy(
                ctypes.string_at(data, ctypes.sizeof(_DeniedEvent)))
            events.append({
                "pid": ev.pid,
                "uid": ev.uid,
                "bpf_cmd": ev.bpf_cmd,
                "comm": ev.comm.decode("utf-8", "replace").rstrip("\x00"),
            })
            return 0

        try:
            poller = RingBufferPoller()
            if poller._lib and poller.attach_ringbuf(fd, _cb):
                # Drain whatever is currently buffered (non-blocking-ish).
                for _ in range(8):
                    if poller.poll(timeout_ms=10) <= 0:
                        break
                poller.free()
        except Exception as e:
            logger.debug(f"Guard denied-events drain error: {e}")
        return events

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
