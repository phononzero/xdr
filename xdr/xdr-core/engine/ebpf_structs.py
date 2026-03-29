"""
eBPF event structures and constants.
Matches struct edr_event / ndr_event in the BPF C programs.
"""

import ctypes

# ---- Alert levels ----
ALERT_INFO = 1
ALERT_WARNING = 2
ALERT_CRITICAL = 3

ALERT_NAMES = {1: "INFO", 2: "WARNING", 3: "CRITICAL"}

# ---- Event types ----
EVT_PROCESS_EXEC = 1
EVT_FILE_OPEN = 2
EVT_NET_CONNECT = 3
EVT_MODULE_LOAD = 4
EVT_PRIV_ESCALATION = 5
EVT_PROCESS_EXIT = 6
EVT_MEMFD_CREATE = 7
EVT_PTRACE = 8

EVT_NAMES = {
    1: "PROCESS_EXEC",
    2: "FILE_OPEN",
    3: "NET_CONNECT",
    4: "MODULE_LOAD",
    5: "PRIV_ESCALATION",
    6: "PROCESS_EXIT",
    7: "MEMFD_CREATE",
    8: "PTRACE",
}

NDR_EVT_NAMES = {
    1: "BLOCKED_IP",
    2: "ARP_SPOOF",
    3: "DNS_TUNNEL",
    4: "NEW_MAC",
}


class EdrEvent(ctypes.Structure):
    """Matches struct edr_event in edr.bpf.c"""
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("event_type", ctypes.c_uint32),
        ("alert_level", ctypes.c_uint32),
        ("ret_code", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("comm", ctypes.c_char * 64),
        ("filename", ctypes.c_char * 256),
        ("argv", ctypes.c_char * 256),   # NEW: full command line
        ("dst_ip", ctypes.c_uint32),
        ("dst_port", ctypes.c_uint16),
        ("_pad", ctypes.c_uint16),
    ]


class NdrEvent(ctypes.Structure):
    """Matches struct ndr_event in ndr.bpf.c"""
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("alert_level", ctypes.c_uint8),
        ("action", ctypes.c_uint8),
        ("event_type", ctypes.c_uint8),
        ("pkt_len", ctypes.c_uint32),
    ]


# Callback type: int (*ring_buffer_sample_fn)(void *ctx, void *data, size_t len)
RING_BUFFER_SAMPLE_FN = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t
)
