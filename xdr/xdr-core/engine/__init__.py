"""
XDR Engine — Modular sub-packages.
Re-exports all components for backward compatibility.
"""

from .ebpf_structs import (
    EdrEvent, NdrEvent, RING_BUFFER_SAMPLE_FN,
    ALERT_INFO, ALERT_WARNING, ALERT_CRITICAL, ALERT_NAMES,
    EVT_PROCESS_EXEC, EVT_FILE_OPEN, EVT_NET_CONNECT,
    EVT_MODULE_LOAD, EVT_PRIV_ESCALATION,
    EVT_PROCESS_EXIT, EVT_MEMFD_CREATE, EVT_PTRACE,
    EVT_NAMES, NDR_EVT_NAMES,
)
from .ring_buffer import RingBufferPoller, get_map_fd_by_name
from .log_manager import LogManager
from .alert_system import AlertSystem
from .correlation import CorrelationEngine
from .utils import ip_str

__all__ = [
    "EdrEvent", "NdrEvent", "RING_BUFFER_SAMPLE_FN",
    "ALERT_INFO", "ALERT_WARNING", "ALERT_CRITICAL", "ALERT_NAMES",
    "EVT_PROCESS_EXEC", "EVT_FILE_OPEN", "EVT_NET_CONNECT",
    "EVT_MODULE_LOAD", "EVT_PRIV_ESCALATION",
    "EVT_PROCESS_EXIT", "EVT_MEMFD_CREATE", "EVT_PTRACE",
    "EVT_NAMES", "NDR_EVT_NAMES",
    "RingBufferPoller", "get_map_fd_by_name",
    "LogManager", "AlertSystem", "CorrelationEngine", "ip_str",
]
