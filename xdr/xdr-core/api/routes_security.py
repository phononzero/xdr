"""
DNS, TLS Fingerprint, File Audit API routes.
"""

from flask import request, jsonify
import api
from api import app


@app.route("/api/dns/stats")
def dns_stats():
    if not api.dns_monitor_ref:
        return jsonify({"error": "not initialized"}), 503
    return jsonify(api.dns_monitor_ref.get_stats())


@app.route("/api/dns/suspicious")
def dns_suspicious():
    if not api.dns_monitor_ref:
        return jsonify([])
    return jsonify(api.dns_monitor_ref.get_suspicious())


@app.route("/api/tls/fingerprints")
def tls_fingerprints():
    if not api.tls_fingerprint_ref:
        return jsonify({"error": "not initialized"}), 503
    return jsonify(api.tls_fingerprint_ref.get_fingerprints())


@app.route("/api/tls/malicious-ja3")
def tls_malicious_ja3():
    if not api.tls_fingerprint_ref:
        return jsonify({})
    return jsonify(api.tls_fingerprint_ref.get_malicious_ja3_list())


@app.route("/api/audit/events")
def audit_events():
    if not api.file_audit_ref:
        return jsonify([])
    limit = request.args.get("limit", 100, type=int)
    return jsonify(api.file_audit_ref.get_events(limit))


@app.route("/api/audit/stats")
def audit_stats():
    if not api.file_audit_ref:
        return jsonify({"error": "not initialized"}), 503
    return jsonify(api.file_audit_ref.get_stats())
