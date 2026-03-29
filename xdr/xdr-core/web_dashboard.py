#!/usr/bin/env python3
"""
XDR Web Dashboard — Flask REST API + SSE for real-time monitoring.
Binds to https://127.0.0.1:29992 (localhost only, TLS 1.3).

Split into api/ subpackage for modularity.
This file is a thin proxy that re-exports for backward compatibility.
"""

# ── Import api package (creates Flask app + shared state) ─
import api

# ── Import all route modules to register Flask routes ─────
import api.middleware       # noqa: F401 — registers @before_request, @after_request
import api.auth             # noqa: F401 — JWT login/refresh/check/logout
import api.spa              # noqa: F401 — registers /, /assets, 404
import api.routes_core      # noqa: F401 — SSE, events, stats, status, search
import api.routes_blocklist  # noqa: F401 — IP/port/PID/MAC/path/hash CRUD
import api.routes_policy    # noqa: F401 — kill-and-block, policy, config reload
import api.routes_integrity  # noqa: F401 — integrity + packages
import api.routes_security  # noqa: F401 — DNS, TLS, file audit
import api.routes_system    # noqa: F401 — processes, network, kernel, health
import api.routes_logs      # noqa: F401 — event log query
import api.routes_whitelist # noqa: F401 — whitelist/blacklist CRUD
import api.routes_assets    # noqa: F401 — asset management (modules, packages, hw)

# ── Re-export for backward compatibility ─────────────────
# xdr_engine.py uses: web_dashboard.app, web_dashboard.push_event,
#   web_dashboard.init_dashboard, web_dashboard.set_*, web_dashboard.start_kernel_checker

app = api.app
push_event = api.push_event
ip_str = api.ip_str


def init_dashboard(store):
    """Initialize with blocklist store reference."""
    api.blocklist_store = store


def set_edr_detector(det):
    api.edr_detector_ref = det


def set_integrity_monitor(im):
    api.integrity_monitor_ref = im


def set_package_monitor(pm):
    api.package_monitor_ref = pm


def set_ssl_probe(sp):
    api._ssl_probe_ref = sp


def set_dns_monitor(dm):
    api.dns_monitor_ref = dm


def set_tls_fingerprint(tf):
    api.tls_fingerprint_ref = tf


def set_file_audit(fa):
    api.file_audit_ref = fa


def set_xdr_engine(engine):
    api._xdr_engine_ref = engine


def start_kernel_checker(interval_secs=3600):
    from api.routes_system import start_kernel_checker as _start
    _start(interval_secs)
