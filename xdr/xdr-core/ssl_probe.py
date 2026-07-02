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
import ctypes.util
import logging
import subprocess
import time
from pathlib import Path
from threading import Thread, Event


# SSL event structure (must match ssl_probe.bpf.c)
MAX_DATA_SIZE = 4096
MAX_COMM_SIZE = 16

# Compiled BPF object locations (installed first, then source tree)
_SSL_OBJ_CANDIDATES = [
    Path("/opt/xdr/xdr-core/ssl_probe.bpf.o"),
    Path(__file__).resolve().parent / "ssl_probe.bpf.o",
]

# eBPF program name → (function symbol, is_uretprobe, library_group)
# library_group: "openssl" or "gnutls" (resolved to a concrete .so at runtime)
_SSL_PROGRAMS = [
    ("uprobe_ssl_write",     "SSL_write",           False, "openssl"),
    ("uretprobe_ssl_write",  "SSL_write",           True,  "openssl"),
    ("uprobe_ssl_read",      "SSL_read",            False, "openssl"),
    ("uretprobe_ssl_read",   "SSL_read",            True,  "openssl"),
    # *_ex variants — CPython 3.x and modern OpenSSL apps call these instead.
    ("uprobe_ssl_write_ex",  "SSL_write_ex",        False, "openssl"),
    ("uretprobe_ssl_write_ex", "SSL_write_ex",      True,  "openssl"),
    ("uprobe_ssl_read_ex",   "SSL_read_ex",         False, "openssl"),
    ("uretprobe_ssl_read_ex", "SSL_read_ex",        True,  "openssl"),
    ("uprobe_gnutls_send",   "gnutls_record_send",  False, "gnutls"),
    ("uretprobe_gnutls_send", "gnutls_record_send", True,  "gnutls"),
    ("uprobe_gnutls_recv",   "gnutls_record_recv",  False, "gnutls"),
    ("uretprobe_gnutls_recv", "gnutls_record_recv", True,  "gnutls"),
]


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


class SSLBpfLoader:
    """Loads ssl_probe.bpf.o via libbpf (ctypes) and attaches SSL uprobes.

    Unlike the tracefs approach — which only produces trace_pipe *metadata*
    (comm/pid) and never the plaintext — this attaches the compiled BPF
    programs so the kernel copies the actual SSL_write/SSL_read buffer into
    the `ssl_events` ring buffer. Returns the ring-buffer map fd for polling.
    """

    def __init__(self):
        self._lib = None
        self._obj = None            # struct bpf_object *
        self._links = []            # struct bpf_link * (keep alive = stay attached)
        self.events_map_fd = -1
        self._load_libbpf()

    def _load_libbpf(self):
        for name in ("libbpf.so.1", "libbpf.so"):
            try:
                self._lib = ctypes.CDLL(name, use_errno=True)
                break
            except OSError:
                continue
        if self._lib is None:
            path = ctypes.util.find_library("bpf")
            if path:
                self._lib = ctypes.CDLL(path, use_errno=True)
        if self._lib is None:
            return
        L = self._lib
        L.bpf_object__open_file.restype = ctypes.c_void_p
        L.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        L.bpf_object__load.restype = ctypes.c_int
        L.bpf_object__load.argtypes = [ctypes.c_void_p]
        L.bpf_object__find_program_by_name.restype = ctypes.c_void_p
        L.bpf_object__find_program_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        L.bpf_program__attach_uprobe.restype = ctypes.c_void_p
        L.bpf_program__attach_uprobe.argtypes = [
            ctypes.c_void_p, ctypes.c_bool, ctypes.c_int,
            ctypes.c_char_p, ctypes.c_size_t,
        ]
        L.bpf_object__find_map_by_name.restype = ctypes.c_void_p
        L.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        L.bpf_map__fd.restype = ctypes.c_int
        L.bpf_map__fd.argtypes = [ctypes.c_void_p]
        L.bpf_object__close.restype = None
        L.bpf_object__close.argtypes = [ctypes.c_void_p]
        if hasattr(L, "bpf_link__destroy"):
            L.bpf_link__destroy.restype = ctypes.c_int
            L.bpf_link__destroy.argtypes = [ctypes.c_void_p]

    @property
    def available(self) -> bool:
        return self._lib is not None

    def load_and_attach(self, obj_path: str, openssl_lib: str | None,
                        gnutls_lib: str | None) -> int:
        """Load the object and attach uprobes. Returns ssl_events map fd, or -1."""
        if not self._lib:
            logging.error("SSL probe: libbpf not available")
            return -1

        obj = self._lib.bpf_object__open_file(obj_path.encode(), None)
        if not obj:
            logging.error(f"SSL probe: bpf_object__open_file failed for {obj_path}")
            return -1
        self._obj = obj

        if self._lib.bpf_object__load(obj) != 0:
            errno = ctypes.get_errno()
            logging.error(f"SSL probe: bpf_object__load failed (errno={errno})")
            self.close()
            return -1

        libs = {"openssl": openssl_lib, "gnutls": gnutls_lib}
        attached = 0
        for prog_name, symbol, is_ret, group in _SSL_PROGRAMS:
            lib_path = libs.get(group)
            if not lib_path:
                continue
            offset = _get_symbol_offset(lib_path, symbol)
            if not offset or offset <= 0:
                logging.warning(f"SSL probe: symbol {symbol} not found in {lib_path}")
                continue
            prog = self._lib.bpf_object__find_program_by_name(obj, prog_name.encode())
            if not prog:
                logging.warning(f"SSL probe: program {prog_name} not in object")
                continue
            # pid=-1 → attach to all processes using the library
            link = self._lib.bpf_program__attach_uprobe(
                prog, is_ret, -1, lib_path.encode(), offset)
            if not link:
                errno = ctypes.get_errno()
                logging.warning(
                    f"SSL probe: attach {prog_name} @ {lib_path}:0x{offset:x} "
                    f"failed (errno={errno})")
                continue
            self._links.append(link)
            attached += 1
            logging.info(
                f"SSL probe: attached {prog_name} @ {lib_path}:0x{offset:x}")

        if attached == 0:
            logging.warning("SSL probe: no uprobes attached")
            self.close()
            return -1

        smap = self._lib.bpf_object__find_map_by_name(obj, b"ssl_events")
        if not smap:
            logging.error("SSL probe: ssl_events map not found in object")
            self.close()
            return -1
        fd = self._lib.bpf_map__fd(smap)
        self.events_map_fd = fd
        logging.info(f"SSL probe: {attached} uprobes attached, ssl_events fd={fd}")
        return fd

    def close(self):
        if self._lib and hasattr(self._lib, "bpf_link__destroy"):
            for link in self._links:
                try:
                    self._lib.bpf_link__destroy(link)
                except Exception:
                    pass
        self._links.clear()
        if self._lib and self._obj:
            try:
                self._lib.bpf_object__close(self._obj)
            except Exception:
                pass
            self._obj = None


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
        self._loader = None           # SSLBpfLoader (libbpf path)
        self._rb_poller = None        # RingBufferPoller on ssl_events
        self.mode = "none"            # "bpf_ringbuf" | "tracefs" | "none"
        self._events_seen = 0
        self._alerts_raised = 0

    def start(self):
        """Start SSL probe in background thread."""
        self._thread = Thread(target=self._run, daemon=True,
                            name="ssl-probe")
        self._thread.start()

    def stop(self):
        """Stop SSL probe."""
        self._stop_event.set()
        # tracefs cleanup (no-op in ring-buffer mode)
        if self.mode != "bpf_ringbuf":
            self._cleanup_probes()
        if self._thread:
            self._thread.join(timeout=5)
        # ring-buffer resources are freed inside _try_bpf_ringbuf on loop exit

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
        """Main probe loop.

        Prefer the libbpf ring-buffer path (captures real plaintext via the
        compiled BPF programs). Only if that is unavailable (no libbpf / no
        compiled object / attach failure) fall back to the legacy tracefs path,
        which yields comm/pid metadata only.
        """
        if self._try_bpf_ringbuf():
            return  # ring-buffer loop ran until stop

        logging.warning("SSL probe: falling back to tracefs metadata mode "
                        "(no plaintext capture)")
        self._run_tracefs()

    # ── libbpf ring-buffer path (real plaintext capture) ────

    def _try_bpf_ringbuf(self) -> bool:
        """Attempt libbpf load + ring-buffer polling. Returns True if it ran."""
        obj_path = next((str(p) for p in _SSL_OBJ_CANDIDATES if p.exists()), None)
        if not obj_path:
            logging.warning("SSL probe: ssl_probe.bpf.o not found "
                           f"(looked in {[str(p) for p in _SSL_OBJ_CANDIDATES]})")
            return False

        openssl_lib = _find_library(OPENSSL_PATHS)
        gnutls_lib = _find_library(GNUTLS_PATHS)
        if not openssl_lib and not gnutls_lib:
            logging.warning("SSL probe: no OpenSSL/GnuTLS library found")
            return False

        loader = SSLBpfLoader()
        if not loader.available:
            logging.warning("SSL probe: libbpf unavailable — cannot use ring buffer")
            return False

        fd = loader.load_and_attach(obj_path, openssl_lib, gnutls_lib)
        if fd < 0:
            loader.close()
            return False

        # Attach ring buffer poller
        try:
            from engine.ring_buffer import RingBufferPoller
        except Exception as e:
            logging.error(f"SSL probe: RingBufferPoller import failed: {e}")
            loader.close()
            return False

        poller = RingBufferPoller()
        if not poller._lib or not poller.attach_ringbuf(fd, self._on_ssl_event):
            logging.error("SSL probe: failed to attach ssl_events ring buffer")
            loader.close()
            return False

        self._loader = loader
        self._rb_poller = poller
        self._attached = True
        self.mode = "bpf_ringbuf"
        self.status = "attached"
        self.status_detail = "eBPF ring buffer 정상 작동 중 (평문 캡처)"
        logging.info("SSL probe: eBPF ring-buffer mode active (plaintext capture)")

        while not self._stop_event.is_set():
            try:
                poller.poll(timeout_ms=200)
            except Exception as e:
                logging.error(f"SSL probe: ring buffer poll error: {e}")
                self._stop_event.wait(1)

        poller.free()
        loader.close()
        return True

    def _on_ssl_event(self, ctx, data, size) -> int:
        """Ring-buffer callback: parse SSLEvent, feed plaintext to detector."""
        try:
            if size < ctypes.sizeof(SSLEvent):
                return 0
            evt = SSLEvent.from_buffer_copy(
                ctypes.string_at(data, ctypes.sizeof(SSLEvent)))
            self._events_seen += 1
            n = min(evt.buf_filled, MAX_DATA_SIZE)
            raw = bytes(bytearray(evt.data[:n]))
            comm = evt.comm.decode("utf-8", "replace").rstrip("\x00")
            event = {
                "pid": evt.pid,
                "tid": evt.tid,
                "uid": evt.uid,
                "comm": comm,
                "direction": "write" if evt.direction == 0 else "read",
                "data": raw,
                "source": "SSL_PROBE",
            }
            if self.detector and hasattr(self.detector, "check_ssl_content"):
                alert = self.detector.check_ssl_content(event)
                if alert and self.push_event:
                    alert["source"] = "SSL_PROBE"
                    alert.setdefault("pid", evt.pid)
                    alert.setdefault("comm", comm)
                    self._alerts_raised += 1
                    self.push_event(alert)
        except Exception as e:
            logging.debug(f"SSL probe: event parse error: {e}")
        return 0

    def get_stats(self) -> dict:
        return {
            "mode": self.mode,
            "status": self.status,
            "events_seen": self._events_seen,
            "alerts_raised": self._alerts_raised,
        }

    # ── legacy tracefs path (metadata only, fallback) ───────

    def _run_tracefs(self):
        """Legacy fallback — attach uprobes via tracefs, parse trace_pipe."""
        self.mode = "tracefs"
        retries = 0
        max_retries = 3
        while not self._stop_event.is_set():
            try:
                if not self._attached:
                    self._attach_probes()
                if self._attached:
                    self.status = "attached"
                    self.status_detail = "uprobe 정상 작동 중 (메타데이터 전용)"
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
