"""
Whitelist / Blacklist management API routes.
Uses edr_detector_ref to read/write policy — ensures consistency with Settings page.
"""

from flask import request, jsonify
import api
from api import app


# ── Whitelist CRUD ──

@app.route("/api/whitelist")
def get_whitelist():
    det = api.edr_detector_ref
    if not det:
        return jsonify([])
    return jsonify(det.policy.get("whitelist_rules", []))


@app.route("/api/whitelist", methods=["POST"])
def add_whitelist():
    rule = request.get_json()
    if not rule or not (rule.get("comm") or rule.get("path")):
        return jsonify({"error": "comm or path required"}), 400

    det = api.edr_detector_ref
    if not det:
        return jsonify({"error": "detector not loaded"}), 500

    rules = det.policy.get("whitelist_rules", [])
    rules.append({
        "comm": rule.get("comm", ""),
        "path": rule.get("path", ""),
        "scope": rule.get("scope", "all"),
        "reason": rule.get("reason", ""),
    })
    det.policy["whitelist_rules"] = rules
    det.update_policy(det.policy)
    return jsonify({"ok": True, "count": len(rules)})


@app.route("/api/whitelist/<int:idx>", methods=["DELETE"])
def delete_whitelist(idx):
    det = api.edr_detector_ref
    if not det:
        return jsonify({"error": "detector not loaded"}), 500

    rules = det.policy.get("whitelist_rules", [])
    if 0 <= idx < len(rules):
        removed = rules.pop(idx)
        det.policy["whitelist_rules"] = rules
        det.update_policy(det.policy)
        return jsonify({"ok": True, "removed": removed})
    return jsonify({"error": "index out of range"}), 404


# ── Blacklist CRUD ──

@app.route("/api/blacklist-rules")
def get_blacklist_rules():
    det = api.edr_detector_ref
    if not det:
        return jsonify([])
    return jsonify(det.policy.get("blacklist_rules", []))


@app.route("/api/blacklist-rules", methods=["POST"])
def add_blacklist_rule():
    rule = request.get_json()
    if not rule or not (rule.get("comm") or rule.get("path")):
        return jsonify({"error": "comm or path required"}), 400

    det = api.edr_detector_ref
    if not det:
        return jsonify({"error": "detector not loaded"}), 500

    rules = det.policy.get("blacklist_rules", [])
    rules.append({
        "comm": rule.get("comm", ""),
        "path": rule.get("path", ""),
        "scope": rule.get("scope", "all"),
        "reason": rule.get("reason", ""),
    })
    det.policy["blacklist_rules"] = rules
    det.update_policy(det.policy)
    return jsonify({"ok": True, "count": len(rules)})


@app.route("/api/blacklist-rules/<int:idx>", methods=["DELETE"])
def delete_blacklist_rule(idx):
    det = api.edr_detector_ref
    if not det:
        return jsonify({"error": "detector not loaded"}), 500

    rules = det.policy.get("blacklist_rules", [])
    if 0 <= idx < len(rules):
        removed = rules.pop(idx)
        det.policy["blacklist_rules"] = rules
        det.update_policy(det.policy)
        return jsonify({"ok": True, "removed": removed})
    return jsonify({"error": "index out of range"}), 404
