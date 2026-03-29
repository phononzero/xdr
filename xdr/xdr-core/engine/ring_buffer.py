"""
Ring Buffer Poller — ctypes wrapper for libbpf ring_buffer API.
"""

import ctypes
import ctypes.util
import logging
import subprocess
import re

from .ebpf_structs import RING_BUFFER_SAMPLE_FN


class RingBufferPoller:
    """Wraps libbpf ring_buffer__new / ring_buffer__poll via ctypes."""

    def __init__(self):
        self._lib = None
        self._rb = None
        self._callbacks = []  # prevent GC of callback references
        self._load_libbpf()

    def _load_libbpf(self):
        try:
            self._lib = ctypes.CDLL("libbpf.so.1")
            logging.info("libbpf.so.1 loaded for ring buffer polling")
        except OSError:
            path = ctypes.util.find_library("bpf")
            if path:
                self._lib = ctypes.CDLL(path)
                logging.info(f"libbpf loaded from {path}")
            else:
                logging.warning("libbpf not found — ring buffer polling disabled")
                self._lib = None

    def attach_ringbuf(self, map_fd: int, callback):
        """Attach a ring buffer map by FD with a sample callback."""
        if not self._lib:
            return False

        cb = RING_BUFFER_SAMPLE_FN(callback)
        self._callbacks.append(cb)  # prevent GC

        if self._rb is None:
            self._lib.ring_buffer__new.restype = ctypes.c_void_p
            self._lib.ring_buffer__new.argtypes = [
                ctypes.c_int, RING_BUFFER_SAMPLE_FN,
                ctypes.c_void_p, ctypes.c_void_p
            ]
            self._rb = self._lib.ring_buffer__new(map_fd, cb, None, None)
            if not self._rb:
                logging.error("ring_buffer__new failed")
                return False
        else:
            self._lib.ring_buffer__add.restype = ctypes.c_int
            self._lib.ring_buffer__add.argtypes = [
                ctypes.c_void_p, ctypes.c_int, RING_BUFFER_SAMPLE_FN,
                ctypes.c_void_p
            ]
            ret = self._lib.ring_buffer__add(self._rb, map_fd, cb, None)
            if ret < 0:
                logging.error(f"ring_buffer__add failed: {ret}")
                return False

        return True

    def poll(self, timeout_ms: int = 100) -> int:
        """Poll the ring buffer. Returns number of events consumed."""
        if not self._lib or not self._rb:
            return -1

        self._lib.ring_buffer__poll.restype = ctypes.c_int
        self._lib.ring_buffer__poll.argtypes = [ctypes.c_void_p, ctypes.c_int]
        return self._lib.ring_buffer__poll(self._rb, timeout_ms)

    def free(self):
        if self._lib and self._rb:
            self._lib.ring_buffer__free.restype = None
            self._lib.ring_buffer__free.argtypes = [ctypes.c_void_p]
            self._lib.ring_buffer__free(self._rb)
            self._rb = None


def get_map_fd_by_name(map_name: str) -> int:
    """Get BPF map FD by name using bpftool map list (text mode, no dump)."""
    try:
        result = subprocess.run(
            ["bpftool", "map", "list"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                match = re.match(r'^\s*(\d+):\s+\S+\s+name\s+(\S+)', line)
                if match and match.group(2) == map_name:
                    map_id = int(match.group(1))
                    return _bpf_map_get_fd_by_id(map_id)
    except Exception as e:
        logging.debug(f"get_map_fd_by_name({map_name}): {e}")
    return -1


def _bpf_map_get_fd_by_id(map_id: int) -> int:
    """Use BPF_MAP_GET_FD_BY_ID syscall to get an FD for a map."""
    BPF_MAP_GET_FD_BY_ID = 14
    SYS_BPF = 321  # x86_64

    class BpfAttr(ctypes.Structure):
        _fields_ = [("map_id", ctypes.c_uint32)]

    attr = BpfAttr(map_id=map_id)
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.syscall(SYS_BPF, BPF_MAP_GET_FD_BY_ID,
                      ctypes.byref(attr), ctypes.sizeof(attr))
    if fd < 0:
        errno = ctypes.get_errno()
        logging.error(f"BPF_MAP_GET_FD_BY_ID({map_id}) failed: errno={errno}")
        return -1
    return fd
