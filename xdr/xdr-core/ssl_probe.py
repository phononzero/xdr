#!/usr/bin/env python3
"""
XDR SSL/TLS Probe — Userspace handler for eBPF SSL uprobe events.

Attaches uprobes to OpenSSL/GnuTLS libraries to capture plaintext
before encryption (SSL_write) and after decryption (SSL_read).
Feeds captured data to EDR detector for content analysis.
"""

import os
import re
import ctypes
import logging
import subprocess
import time
from pathlib import Path
from threading import Thread, Event


# SSL event structure (must match ssl_probe.bpf.c)
MAX_DATA_SIZE = 4096
MAX_COMM_SIZE = 16


class SSLEvent(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("tid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("len", ctypes.c_uint32),
        ("buf_filled", ctypes.c_uint32),
        ("direction", ctypes.c_uint8),
        ("comm", ctypes.c_char * MAX_COMM_SIZE),
        ("data", ctypes.c_uint8 * MAX_DATA_SIZE),
    ]


# Known library paths for OpenSSL and GnuTLS
OPENSSL_PATHS = [
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/usr/lib/libssl.so.3",
    "/usr/lib/libssl.so.1.1",
    "/lib/x86_64-linux-gnu/libssl.so.3",
    "/lib/x86_64-linux-gnu/libssl.so.1.1",
]

GNUTLS_PATHS = [
    "/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
    "/usr/lib/libgnutls.so.30",
    "/lib/x86_64-linux-gnu/libgnutls.so.30",
]


def _find_library(paths: list[str]) -> str | None:
    """Find first existing library from candidate paths."""
    for p in paths:
        if os.path.exists(p):
            return p
    # Try ldconfig
    try:
        result = subprocess.run(
            ["ldconfig", "-p"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            for search in ["libssl.so.3", "libssl.so.1.1"]:
                if search in line and "x86-64" in line:
                    path = line.split("=>")[-1].strip()
                    if os.path.exists(path):
                        return path
    except Exception:
        pass
    return None


def _get_symbol_offset(lib_path: str, symbol: str) -> int | None:
    """Get symbol offset in shared library using readelf (most reliable)."""
    # Method 1: readelf -Ws (handles versioned symbols well)
    try:
        result = subprocess.run(
            ["readelf", "-Ws", lib_path],
            capture_output=True, text=True, timeout=10
        )
        # Pattern: "   654: 000000000003cbf0    33 FUNC    GLOBAL DEFAULT   13 SSL_read_ex@@OPENSSL_3.0.0"
        for line in result.stdout.splitlines():
            if "FUNC" in line and "GLOBAL" in line:
                cols = line.split()
                if len(cols) >= 8:
                    # Last column: "SSL_read@@OPENSSL_3.0.0" or "SSL_read"
                    raw_sym = cols[-1].split("@@")[0].split("@")[0]
                    if raw_sym == symbol:
                        # Address is the second column (after index:)
                        addr_str = cols[1].rstrip(":")
                        return int(addr_str, 16)
    except Exception as e:
        logging.debug(f"readelf failed for {symbol}: {e}")

    # Method 2: nm -D fallback
    try:
        result = subprocess.run(
            ["nm", "-D", lib_path], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                sym_name = parts[2].split("@@")[0].split("@")[0]
                if sym_name == symbol:
                    return int(parts[0], 16)
    except Exception as e:
        logging.debug(f"nm failed for {symbol}: {e}")

    return None


def _find_tracefs() -> Path | None:
    """Find writable tracefs uprobe_events path."""
    candidates = [
        Path("/sys/kernel/tracing/uprobe_events"),
        Path("/sys/kernel/debug/tracing/uprobe_events"),
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


class SSLProbe:
    """Manages SSL/TLS eBPF uprobes for plaintext capture."""

    def __init__(self, edr_detector=None, push_event_fn=None):
        self.detector = edr_detector
        self.push_event = push_event_fn
        self._stop_event = Event()
        self._thread = None
        self._bpf = None
        self._attached = False
        self.status = "not_started"   # not_started | attached | attach_failed | error
        self.status_detail = ""
        self._attached_probes = []    # track registered probe names for cleanup

    def start(self):
        """Start SSL probe in background thread."""
        self._thread = Thread(target=self._run, daemon=True,
                            name="ssl-probe")
        self._thread.start()

    def stop(self):
        """Stop SSL probe."""
        self._stop_event.set()
        self._cleanup_probes()
        if self._thread:
            self._thread.join(timeout=5)

    def _cleanup_probes(self):
        """Remove registered uprobe events."""
        tracefs = _find_tracefs()
        if not tracefs:
            return
        tf = str(tracefs)
        for name in self._attached_probes:
            subprocess.run(
                f'echo "-:{name}" >> {tf}',
                shell=True, capture_output=True, timeout=5
            )
        self._attached_probes.clear()

    @staticmethod
    def _tracefs_write(path: str, data: str):
        """Write to a tracefs file using os.open (no O_CREAT flag).
        
        Python's open('a') includes O_CREAT which tracefs rejects with EINVAL.
        Must use os.open with O_WRONLY only.
        """
        fd = os.open(path, os.O_WRONLY)
        try:
            os.write(fd, data.encode())
        finally:
            os.close(fd)

    def _cleanup_all_xdr_probes(self, tracefs: Path):
        """Remove ALL xdr-related uprobe events from tracefs.
        
        Must disable each probe BEFORE deleting, otherwise kernel returns
        I/O error (EBUSY) on the delete write.
        """
        try:
            with open(str(tracefs), "r") as f:
                lines = f.readlines()

            tracefs_base = str(tracefs.parent)  # /sys/kernel/tracing

            for line in lines:
                if "xdr" not in line.lower():
                    continue
                parts = line.strip().split()
                if not parts:
                    continue

                # Extract full name: "p:uprobes/xdr_u_ssl_write" -> "uprobes/xdr_u_ssl_write"
                full_name = parts[0].split(":", 1)[-1]
                short_name = full_name.split("/")[-1]

                # Step 1: DISABLE the probe first (critical!)
                enable_path = os.path.join(tracefs_base, "events", "uprobes",
                                          short_name, "enable")
                if os.path.exists(enable_path):
                    try:
                        with open(enable_path, "w") as f:
                            f.write("0")
                        logging.debug(f"SSL probe: disabled {short_name}")
                    except Exception as e:
                        logging.debug(f"SSL probe: disable {short_name}: {e}")

                # Step 2: DELETE the probe
                try:
                    self._tracefs_write(str(tracefs), f"-:{full_name}\n")
                    logging.info(f"SSL probe: cleaned up old probe: {full_name}")
                except Exception as e:
                    logging.debug(f"SSL probe: delete {full_name}: {e}")

        except Exception as e:
            logging.debug(f"SSL probe: cleanup error: {e}")

    def _run(self):
        """Main probe loop — attach uprobes and process events."""
        retries = 0
        max_retries = 3
        while not self._stop_event.is_set():
            try:
                if not self._attached:
                    self._attach_probes()
                if self._attached:
                    self.status = "attached"
                    self.status_detail = "uprobe 정상 작동 중"
                    retries = 0
                    self._process_events()
                else:
                    retries += 1
                    self.status = "attach_failed"
                    self.status_detail = (f"uprobe attach 실패 "
                                         f"(시도 {retries}/{max_retries})")
                    logging.warning(f"SSL probe: {self.status_detail}")
                    if retries >= max_retries:
                        self.status_detail += " — ssl_probe.bpf.o 확인 필요"
                        logging.error("SSL probe: max retries reached. "
                                    "Check ssl_probe.bpf.o exists.")
                        # Alert via dashboard
                        if self.push_event:
                            self.push_event({
                                "source": "SSL_PROBE",
                                "action": "ALERT",
                                "reason": "PROBE_ATTACH_FAILED",
                                "detail": self.status_detail,
                                "alert_level": 2,
                            })
                        # Keep thread alive but stop retrying
                        self._stop_event.wait()
                        return
                    self._stop_event.wait(30)
            except Exception as e:
                self.status = "error"
                self.status_detail = str(e)
                logging.error(f"SSL probe error: {e}")
                self._stop_event.wait(30)

    def _attach_probes(self):
        """Attach eBPF uprobes to SSL libraries via tracefs."""
        # Find tracefs
        tracefs = _find_tracefs()
        if not tracefs:
            logging.error("SSL probe: tracefs uprobe_events not found")
            return

        # Find libraries
        openssl_path = _find_library(OPENSSL_PATHS)
        gnutls_path = _find_library(GNUTLS_PATHS)

        logging.info(f"SSL probe: OpenSSL={openssl_path}, GnuTLS={gnutls_path}")

        if not openssl_path and not gnutls_path:
            logging.warning("SSL probe: no SSL/TLS libraries found")
            return

        # Clean up any leftover probes from previous runs
        self._cleanup_all_xdr_probes(tracefs)

        attached_count = 0

        # Attach OpenSSL probes
        if openssl_path:
            for func in ["SSL_write", "SSL_read"]:
                offset = _get_symbol_offset(openssl_path, func)
                if offset is not None and offset > 0:
                    logging.info(f"SSL probe: {func} @ 0x{offset:x}")
                    fname = func.lower()  # tracefs requires lowercase
                    # uprobe (entry)
                    if self._register_uprobe(
                            tracefs, f"xdr_u_{fname}", openssl_path,
                            offset, is_ret=False):
                        attached_count += 1
                    # uretprobe (return)
                    if self._register_uprobe(
                            tracefs, f"xdr_r_{fname}", openssl_path,
                            offset, is_ret=True):
                        attached_count += 1
                else:
                    logging.warning(f"SSL probe: symbol {func} not found "
                                  f"in {openssl_path}")

        # Attach GnuTLS probes
        if gnutls_path:
            for func in ["gnutls_record_send", "gnutls_record_recv"]:
                offset = _get_symbol_offset(gnutls_path, func)
                if offset is not None and offset > 0:
                    logging.info(f"SSL probe: {func} @ 0x{offset:x}")
                    if self._register_uprobe(
                            tracefs, f"xdr_u_{func}", gnutls_path,
                            offset, is_ret=False):
                        attached_count += 1
                    if self._register_uprobe(
                            tracefs, f"xdr_r_{func}", gnutls_path,
                            offset, is_ret=True):
                        attached_count += 1
                else:
                    logging.warning(f"SSL probe: symbol {func} not found "
                                  f"in {gnutls_path}")

        self._attached = attached_count > 0
        if self._attached:
            logging.info(f"SSL probe: {attached_count} probes attached "
                        f"successfully")
        else:
            logging.warning("SSL probe: failed to attach any probes")

    def _register_uprobe(self, tracefs: Path, event_name: str,
                         lib_path: str, offset: int,
                         is_ret: bool) -> bool:
        """Register a single uprobe/uretprobe via tracefs using direct file I/O."""
        try:
            probe_char = "r" if is_ret else "p"
            tf = str(tracefs)
            tracefs_base = str(tracefs.parent)
            full_event_name = f"uprobes/{event_name}"

            # Step 1: Disable existing probe if present
            enable_path = os.path.join(tracefs_base, "events", "uprobes",
                                      event_name, "enable")
            if os.path.exists(enable_path):
                try:
                    with open(enable_path, "w") as f:
                        f.write("0")
                except Exception:
                    pass

            # Step 2: Remove existing probe if any
            try:
                self._tracefs_write(tf, f"-:{full_event_name}\n")
            except Exception:
                pass  # May not exist, that's fine

            # Step 3: Register new probe
            probe_def = f"{probe_char}:{full_event_name} {lib_path}:0x{offset:x}\n"
            logging.info(f"SSL probe: registering: {probe_def.strip()}")
            try:
                self._tracefs_write(tf, probe_def)
            except OSError as e:
                logging.error(f"SSL probe: write failed for {event_name}: {e}")
                return False

            # Step 4: Enable the probe
            # Re-check enable path (it should exist now after registration)
            if os.path.exists(enable_path):
                try:
                    with open(enable_path, "w") as f:
                        f.write("1")
                except Exception as e:
                    logging.debug(f"SSL probe: enable {event_name}: {e}")

            self._attached_probes.append(event_name)
            logging.info(f"SSL probe: registered {probe_char}probe "
                        f"{event_name} @ {lib_path}:0x{offset:x}")
            return True

        except PermissionError:
            logging.error(f"SSL probe: permission denied writing tracefs "
                        f"(need root)")
            return False
        except OSError as e:
            logging.error(f"SSL probe: tracefs write failed for "
                        f"{event_name}: {e}")
            return False

    def _process_events(self):
        """Process SSL events by reading trace_pipe."""
        logging.info("SSL probe: monitoring TLS plaintext via trace_pipe...")

        # Read from trace_pipe for uprobe events
        trace_pipe = None
        for path in ["/sys/kernel/tracing/trace_pipe",
                     "/sys/kernel/debug/tracing/trace_pipe"]:
            if os.path.exists(path):
                trace_pipe = path
                break

        if not trace_pipe:
            logging.error("SSL probe: trace_pipe not found")
            return

        try:
            with open(trace_pipe, "r") as f:
                while not self._stop_event.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    if "xdr_" in line:
                        self._handle_trace_line(line.strip())
        except OSError as e:
            logging.error(f"SSL probe: trace_pipe error: {e}")

    def _handle_trace_line(self, line: str):
        """Parse a trace_pipe line from uprobe event."""
        # Format: "  command-PID  [CPU] timestamp: event_name: (addr) args"
        try:
            # Extract comm and PID
            match = re.match(r'\s*(.+?)-(\d+)\s+\[', line)
            if not match:
                return

            comm = match.group(1).strip()
            pid = int(match.group(2))

            # Determine direction from event name
            is_write = "SSL_write" in line or "gnutls_record_send" in line
            direction = "write" if is_write else "read"

            event = {
                "pid": pid,
                "comm": comm,
                "direction": direction,
                "source": "SSL_PROBE",
            }

            # Skip pushing every TLS read/write as individual events
            # (was flooding dashboard with hundreds of INFO events per second)
            # Only alert-worthy SSL content from detector will be pushed below

            # Feed to EDR detector for content analysis
            if self.detector and hasattr(self.detector, 'check_ssl_content'):
                alert = self.detector.check_ssl_content(event)
                if alert and self.push_event:
                    alert["source"] = "SSL_PROBE"
                    self.push_event(alert)

        except Exception as e:
            logging.debug(f"SSL trace parse error: {e}")
