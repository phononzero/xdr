"""
System API routes — processes, network, kernel update, health, process tree.
"""

import re
import os
import time
import json
import socket
import struct
import logging
import subprocess
import urllib.request
from datetime import datetime
from threading import Thread, Lock

from flask import request, jsonify
import api
from api import app, push_event


def _ip_int_to_str(ip_int: int) -> str:
    """Convert 32-bit int IP to dotted string."""
    if ip_int == 0:
        return "0.0.0.0"
    try:
        return socket.inet_ntoa(struct.pack("!I", ip_int))
    except (struct.error, OSError):
        return str(ip_int)

# ── Process Tree API ─────────────────────────────────────

@app.route("/api/process-tree")
def get_process_tree():
    if not api.edr_detector_ref:
        return jsonify([])
    return jsonify(api.edr_detector_ref.get_process_tree())


@app.route("/api/process-chain/<int:pid>")
def get_process_chain(pid):
    if not api.edr_detector_ref:
        return jsonify([])
    return jsonify(api.edr_detector_ref.get_process_chain(pid))


# ── Module Health API ────────────────────────────────────

@app.route("/api/health")
def health_check():
    import threading

    def _thread_status(name: str) -> str:
        for t in threading.enumerate():
            if t.name == name:
                return "running" if t.is_alive() else "stopped"
        return "not_started"

    # ssl_probe: use actual attach status
    ssl_status = "not_started"
    ssl_detail = ""
    if api._ssl_probe_ref is not None:
        ssl_status = api._ssl_probe_ref.status
        ssl_detail = api._ssl_probe_ref.status_detail

    ssl_health = {
        "not_started": "not_started",
        "attached": "running",
        "attach_failed": "failed",
        "error": "failed",
    }.get(ssl_status, ssl_status)

    modules = {
        "edr_detector": "running" if api.edr_detector_ref else "stopped",
        "integrity": _thread_status("integrity"),
        "packages": _thread_status("packages"),
        "ssl_probe": ssl_health,
        "dns_monitor": _thread_status("dns-monitor"),
        "file_audit": _thread_status("file-audit"),
    }

    details = {}
    if ssl_health != "running" and ssl_detail:
        details["ssl_probe"] = ssl_detail

    all_ok = all(v == "running" for v in modules.values())
    return jsonify({
        "status": "healthy" if all_ok else "degraded",
        "uptime_seconds": int(time.time() - api._start_time),
        "modules": modules,
        "details": details,
        "timestamp": datetime.now().isoformat(),
    })


# ── Process List API ─────────────────────────────────────

@app.route("/api/processes")
def get_processes():
    procs = _read_proc_list()
    if not procs:
        procs = _read_ps_fallback()

    # Enrich from proc_cache (eBPF exec events)
    engine = api._xdr_engine_ref
    if engine:
        pcache = engine.get_proc_cache()
        for p in procs:
            pid = p.get("pid", 0)
            if pid in pcache:
                cached = pcache[pid]
                if not p.get("exe") or p["exe"] == "":
                    p["exe"] = cached.get("exe", "")
                    p["enriched"] = True
                if not p.get("cmdline") or p["cmdline"] == "":
                    p["cmdline"] = cached.get("cmdline", "")
                    p["enriched"] = True
                if not p.get("comm") or p["comm"] == "":
                    p["comm"] = cached.get("comm", "")
                    p["enriched"] = True

    return jsonify(procs)


def _read_proc_list():
    procs = []
    try:
        for name in os.listdir("/proc"):
            if not name.isdigit():
                continue
            pid = int(name)
            if pid <= 2:
                continue
            info = {"pid": pid, "ppid": 0, "uid": -1, "state": "",
                    "rss_kb": 0, "comm": "", "exe": "", "cmdline": ""}
            base = "/proc/" + name
            try:
                with open(base + "/status", "r") as f:
                    for line in f:
                        if line.startswith("Name:"):
                            info["comm"] = line[5:].strip()
                        elif line.startswith("State:"):
                            info["state"] = line[6:].strip().split()[0]
                        elif line.startswith("PPid:"):
                            info["ppid"] = int(line[5:].strip())
                        elif line.startswith("Uid:"):
                            info["uid"] = int(line[4:].strip().split()[0])
                        elif line.startswith("VmRSS:"):
                            info["rss_kb"] = int(line[6:].strip().split()[0])
            except (OSError, ValueError):
                continue
            try:
                info["exe"] = os.readlink(base + "/exe")
            except OSError:
                # Kernel threads (ppid <= 2) have no exe
                if info["ppid"] <= 2:
                    info["exe"] = "[kernel]"
            try:
                with open(base + "/cmdline", "rb") as f:
                    raw = f.read(512)
                info["cmdline"] = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
                if not info["cmdline"] and info["ppid"] <= 2:
                    info["cmdline"] = "[kernel thread]"
            except OSError:
                if info["ppid"] <= 2:
                    info["cmdline"] = "[kernel thread]"
            procs.append(info)
    except Exception as e:
        logging.debug(f"/proc read error: {e}")
    return procs


def _read_ps_fallback():
    procs = []
    try:
        result = subprocess.run(
            ["ps", "axo", "pid,ppid,uid,stat,rss,comm,args", "--no-headers", "-ww"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split(None, 6)
                if len(parts) < 6:
                    continue
                try:
                    pid = int(parts[0])
                    if pid <= 2:
                        continue
                    procs.append({
                        "pid": pid, "ppid": int(parts[1]), "uid": int(parts[2]),
                        "state": parts[3], "rss_kb": int(parts[4]),
                        "comm": parts[5],
                        "exe": parts[6] if len(parts) > 6 else parts[5],
                        "cmdline": parts[6] if len(parts) > 6 else "",
                    })
                except (ValueError, IndexError):
                    continue
    except Exception as e:
        logging.debug(f"ps fallback error: {e}")
    return procs


# ── Network Connections API ──────────────────────────────

@app.route("/api/connections")
def get_connections():
    connections = []
    try:
        result = subprocess.run(
            ["ss", "-tunap", "--no-header"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                conn = _parse_ss_line(line)
                if conn:
                    connections.append(conn)
    except Exception as e:
        logging.debug(f"Connections error: {e}")

    # Enrich PID=0 connections from conn_cache (eBPF connect events)
    engine = api._xdr_engine_ref
    if engine:
        ccache = engine.get_conn_cache()
        for c in connections:
            if c.get("pid", 0) == 0 and c.get("peer_addr"):
                # Try lookup by (dst_ip_int, dst_port)
                peer = c["peer_addr"]
                peer_port = c.get("peer_port", 0)
                # Convert peer IP string to int for cache lookup
                try:
                    ip_int = struct.unpack("!I", socket.inet_aton(peer))[0]
                    dst_key = (ip_int, peer_port)
                    if dst_key in ccache:
                        cached = ccache[dst_key]
                        c["pid"] = cached.get("pid", 0)
                        c["comm"] = cached.get("comm", "")
                        c["exe"] = cached.get("exe", "")
                        c["enriched"] = True
                except (socket.error, struct.error):
                    pass

    return jsonify(connections)


def _parse_ss_line(line: str) -> dict | None:
    parts = line.split()
    if len(parts) < 5:
        return None

    proto = parts[0]
    state = parts[1] if proto == "tcp" else ""
    local_raw = parts[3] if proto == "tcp" else parts[2]
    peer_raw = parts[4] if proto == "tcp" else parts[3]

    local_addr, local_port = _split_addr_port(local_raw)
    peer_addr, peer_port = _split_addr_port(peer_raw)

    proc_info = ""
    pid = 0
    comm = ""
    for p in parts:
        if "users:" in p:
            proc_info = p
            break

    if proc_info:
        m = re.search(r'"([^"]+)",pid=(\d+)', proc_info)
        if m:
            comm = m.group(1)
            pid = int(m.group(2))

    return {
        "proto": proto,
        "state": state,
        "local_addr": local_addr,
        "local_port": local_port,
        "peer_addr": peer_addr,
        "peer_port": peer_port,
        "pid": pid,
        "comm": comm,
    }


def _split_addr_port(raw: str) -> tuple:
    if raw.startswith("["):
        bracket = raw.rfind("]")
        addr = raw[1:bracket]
        port = raw[bracket+2:] if bracket+2 < len(raw) else "0"
    elif raw.count(":") > 1:
        addr = raw
        port = "0"
    else:
        parts = raw.rsplit(":", 1)
        addr = parts[0] if parts else raw
        port = parts[1] if len(parts) > 1 else "0"
    try:
        port = int(port)
    except ValueError:
        port = 0
    return addr, port


# ── Kernel Update Checker ────────────────────────────────

_kernel_update_info = {"current": "", "latest": "", "has_update": False,
                       "last_check": None, "error": None}
_kernel_check_lock = Lock()


def _check_kernel_updates():
    global _kernel_update_info
    current = os.uname().release.split("-")[0]

    try:
        req = urllib.request.Request(
            "https://www.kernel.org/releases.json",
            headers={"User-Agent": "XDR-Kernel-Checker/1.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        latest_612 = None
        for release in data.get("releases", []):
            ver = release.get("version", "")
            if ver.startswith("6.12."):
                if latest_612 is None or _version_compare(ver, latest_612) > 0:
                    latest_612 = ver

        with _kernel_check_lock:
            _kernel_update_info = {
                "current": current,
                "latest": latest_612 or current,
                "has_update": latest_612 is not None and _version_compare(latest_612, current) > 0,
                "last_check": datetime.now().isoformat(),
                "error": None,
            }

        if _kernel_update_info["has_update"]:
            push_event({
                "source": "SYSTEM", "action": "KERNEL_UPDATE",
                "target": f"{current} → {latest_612}",
                "alert_level": 2, "event_type": "kernel",
                "message": f"새 커널 릴리즈: {latest_612} (현재: {current})",
            })

    except Exception as e:
        with _kernel_check_lock:
            _kernel_update_info["error"] = str(e)
            _kernel_update_info["last_check"] = datetime.now().isoformat()


def _version_compare(v1: str, v2: str) -> int:
    parts1 = [int(x) for x in v1.split(".")]
    parts2 = [int(x) for x in v2.split(".")]
    for a, b in zip(parts1, parts2):
        if a > b:
            return 1
        if a < b:
            return -1
    return len(parts1) - len(parts2)


def start_kernel_checker(interval_secs=3600):
    def loop():
        import time as _time
        while True:
            _check_kernel_updates()
            _time.sleep(interval_secs)
    t = Thread(target=loop, daemon=True)
    t.start()
    logging.info(f"Kernel update checker started (interval={interval_secs}s)")


@app.route("/api/kernel-update")
def get_kernel_update():
    with _kernel_check_lock:
        return jsonify(_kernel_update_info)


@app.route("/api/kernel-update/check", methods=["POST"])
def force_kernel_check():
    Thread(target=_check_kernel_updates, daemon=True).start()
    return jsonify({"ok": True, "message": "check initiated"})
