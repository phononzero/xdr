"""
Blocklist CRUD API routes — IP, port, PID, MAC, path, hash, CIDR.
"""

import ipaddress
import socket

from flask import request, jsonify
import api
from api import app, push_event


@app.route("/api/blocklists")
def get_blocklists():
    if not api.blocklist_store:
        return jsonify({"error": "store not initialized"}), 503
    return jsonify(api.blocklist_store.get_all())


@app.route("/api/blocklists/ip", methods=["POST"])
def add_blocked_ip():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    try:
        socket.inet_aton(ip)
    except socket.error:
        return jsonify({"error": "invalid IP"}), 400
    ok = api.blocklist_store.add_blocked_ip(ip)
    push_event({"source": "ADMIN", "action": "BLOCK_IP", "target": ip,
                "alert_level": 2, "event_type": "admin"})
    return jsonify({"ok": ok, "ip": ip})


@app.route("/api/blocklists/ip/<ip>", methods=["DELETE"])
def del_blocked_ip(ip):
    ok = api.blocklist_store.remove_blocked_ip(ip)
    push_event({"source": "ADMIN", "action": "UNBLOCK_IP", "target": ip,
                "alert_level": 1, "event_type": "admin"})
    return jsonify({"ok": ok, "ip": ip})


@app.route("/api/blocklists/port", methods=["POST"])
def add_blocked_port():
    data = request.get_json(silent=True) or {}
    port = data.get("port", 0)
    try:
        port = int(port)
        if not (1 <= port <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "valid port (1-65535) required"}), 400
    ok = api.blocklist_store.add_blocked_port(port)
    push_event({"source": "ADMIN", "action": "BLOCK_PORT", "target": str(port),
                "alert_level": 2, "event_type": "admin"})
    return jsonify({"ok": ok, "port": port})


@app.route("/api/blocklists/port/<int:port>", methods=["DELETE"])
def del_blocked_port(port):
    ok = api.blocklist_store.remove_blocked_port(port)
    push_event({"source": "ADMIN", "action": "UNBLOCK_PORT", "target": str(port),
                "alert_level": 1, "event_type": "admin"})
    return jsonify({"ok": ok, "port": port})


@app.route("/api/blocklists/pid", methods=["POST"])
def add_blocked_pid():
    data = request.get_json(silent=True) or {}
    try:
        pid = int(data.get("pid", 0))
        if pid <= 0:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "valid PID required"}), 400
    ok = api.blocklist_store.add_blocked_pid(pid)
    push_event({"source": "ADMIN", "action": "BLOCK_PID", "target": str(pid),
                "alert_level": 3, "event_type": "admin"})
    return jsonify({"ok": ok, "pid": pid})


@app.route("/api/blocklists/pid/<int:pid>", methods=["DELETE"])
def del_blocked_pid(pid):
    ok = api.blocklist_store.remove_blocked_pid(pid)
    push_event({"source": "ADMIN", "action": "UNBLOCK_PID", "target": str(pid),
                "alert_level": 1, "event_type": "admin"})
    return jsonify({"ok": ok, "pid": pid})


@app.route("/api/blocklists/mac", methods=["POST"])
def add_known_mac():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    mac = data.get("mac", "").strip()
    if not ip or not mac:
        return jsonify({"error": "ip and mac required"}), 400
    ok = api.blocklist_store.add_known_mac(ip, mac)
    return jsonify({"ok": ok, "ip": ip, "mac": mac})


@app.route("/api/blocklists/mac/<ip>", methods=["DELETE"])
def del_known_mac(ip):
    ok = api.blocklist_store.remove_known_mac(ip)
    return jsonify({"ok": ok, "ip": ip})


@app.route("/api/blocklists/path", methods=["POST"])
def add_blocked_path():
    data = request.get_json(silent=True) or {}
    path = data.get("path", "").strip()
    if not path:
        return jsonify({"error": "path required"}), 400
    ok = api.blocklist_store.add_blocked_path(path)
    push_event({"source": "ADMIN", "action": "BLOCK_PATH", "target": path,
                "alert_level": 2, "event_type": "admin"})
    return jsonify({"ok": ok, "path": path})


@app.route("/api/blocklists/path", methods=["DELETE"])
def del_blocked_path():
    data = request.get_json(silent=True) or {}
    path = data.get("path", "").strip()
    if not path:
        return jsonify({"error": "path required"}), 400
    ok = api.blocklist_store.remove_blocked_path(path)
    push_event({"source": "ADMIN", "action": "UNBLOCK_PATH", "target": path,
                "alert_level": 1, "event_type": "admin"})
    return jsonify({"ok": ok, "path": path})


@app.route("/api/blocklists/hash", methods=["POST"])
def add_blocked_hash():
    data = request.get_json(silent=True) or {}
    sha256 = data.get("hash", "").strip()
    name = data.get("name", "").strip()
    reason = data.get("reason", "수동 등록").strip()
    if not sha256 or len(sha256) != 64:
        return jsonify({"error": "valid SHA256 hash (64 hex chars) required"}), 400
    ok = api.blocklist_store.add_blocked_hash(sha256, name, reason)
    push_event({"source": "ADMIN", "action": "BLOCK_HASH",
                "target": f"{sha256[:16]}... ({name})",
                "alert_level": 2, "event_type": "admin"})
    return jsonify({"ok": ok, "hash": sha256})


@app.route("/api/blocklists/hash/<sha256>", methods=["DELETE"])
def del_blocked_hash(sha256):
    ok = api.blocklist_store.remove_blocked_hash(sha256)
    push_event({"source": "ADMIN", "action": "UNBLOCK_HASH",
                "target": sha256[:16] + "...",
                "alert_level": 1, "event_type": "admin"})
    return jsonify({"ok": ok, "hash": sha256})


# ── CIDR Block Management ─────────────────────────────────────────────────────

@app.route("/api/blocklists/cidr", methods=["POST"])
def add_blocked_cidr():
    """Block an entire CIDR range via nftables. Body: {cidr, asn, label, reason}"""
    data = request.get_json(silent=True) or {}
    cidr = data.get("cidr", "").strip()
    if not cidr:
        return jsonify({"error": "cidr required"}), 400
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return jsonify({"error": f"invalid CIDR: {cidr}"}), 400
    ok = api.blocklist_store.add_blocked_cidr(
        cidr=cidr,
        asn=data.get("asn", ""),
        label=data.get("label", ""),
        reason=data.get("reason", "수동 등록"),
    )
    push_event({"source": "ADMIN", "action": "BLOCK_CIDR", "target": cidr,
                "alert_level": 2, "event_type": "admin"})
    return jsonify({"ok": ok, "cidr": cidr})


@app.route("/api/blocklists/cidr", methods=["DELETE"])
def del_blocked_cidr():
    """Unblock a CIDR range. Body: {cidr}"""
    data = request.get_json(silent=True) or {}
    cidr = data.get("cidr", "").strip()
    if not cidr:
        return jsonify({"error": "cidr required"}), 400
    ok = api.blocklist_store.remove_blocked_cidr(cidr)
    push_event({"source": "ADMIN", "action": "UNBLOCK_CIDR", "target": cidr,
                "alert_level": 1, "event_type": "admin"})
    return jsonify({"ok": ok, "cidr": cidr})
