"""
XDR API package — shared state and Flask app instance.

All route files import from this module to access shared state.
web_dashboard.py re-exports everything for backward compatibility.
"""

import json
import time
import os
import struct
import socket
import logging
from queue import Queue, Empty
from datetime import datetime
from threading import Lock

from flask import Flask

# ── Flask App ────────────────────────────────────────────
app = Flask(__name__, static_folder="../static", static_url_path="/static")
app.config["SECRET_KEY"] = "xdr-local-only"

# ── Shared State ─────────────────────────────────────────
blocklist_store = None
event_history = []
event_history_lock = Lock()
MAX_EVENT_HISTORY = 5000

# SSE subscribers
sse_queues: list[Queue] = []
sse_lock = Lock()

# Module references (set by xdr_engine via setters)
edr_detector_ref = None
integrity_monitor_ref = None
package_monitor_ref = None
dns_monitor_ref = None
tls_fingerprint_ref = None
file_audit_ref = None
_ssl_probe_ref = None
_xdr_engine_ref = None  # XDREngine instance (for conn_cache / proc_cache)

_start_time = time.time()


def push_event(event: dict):
    """Push event to SSE subscribers, history, and persistent store."""
    event["_time"] = datetime.now().isoformat()

    with event_history_lock:
        event_history.append(event)
        if len(event_history) > MAX_EVENT_HISTORY:
            del event_history[:len(event_history) - MAX_EVENT_HISTORY]

    # Persist to SQLite + disguised backup
    try:
        import sys
        _core_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _core_dir not in sys.path:
            sys.path.insert(0, _core_dir)
        from event_store import get_event_store
        get_event_store().store(event)
    except Exception as _e:
        import logging
        logging.debug(f"EventStore persist error: {_e}")

    data = json.dumps(event, default=str)
    with sse_lock:
        dead = []
        for q in sse_queues:
            try:
                q.put_nowait(data)
            except Exception:
                dead.append(q)
        for q in dead:
            sse_queues.remove(q)


def ip_str(ip_int: int) -> str:
    """Convert a 32-bit integer IP to dotted string."""
    if ip_int == 0:
        return "0.0.0.0"
    try:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    except (struct.error, OSError):
        return str(ip_int)
