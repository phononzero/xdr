"""
Policy + kill-and-block API routes.
"""

from flask import request, jsonify
import api
from api import app, push_event


@app.route("/api/kill-and-block", methods=["POST"])
def kill_and_block():
    data = request.get_json(silent=True) or {}
    try:
        pid = int(data.get("pid", 0))
        if pid <= 0:
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({"error": "valid PID required"}), 400

    if not api.edr_detector_ref:
        return jsonify({"error": "detector not initialized"}), 503

    result = api.edr_detector_ref.kill_and_block(pid)
    push_event({
        "source": "ADMIN", "action": "KILL_AND_BLOCK",
        "target": f"PID {pid} → {result.get('path', '?')}",
        "alert_level": 3, "event_type": "admin",
        "detail": result,
    })
    return jsonify(result)


@app.route("/api/policy")
def get_policy():
    if not api.edr_detector_ref:
        return jsonify({"error": "detector not initialized"}), 503
    return jsonify(api.edr_detector_ref.get_policy())


@app.route("/api/policy", methods=["POST"])
def update_policy():
    if not api.edr_detector_ref:
        return jsonify({"error": "detector not initialized"}), 503
    data = request.get_json(silent=True) or {}
    new_policy = api.edr_detector_ref.update_policy(data)
    push_event({
        "source": "ADMIN", "action": "POLICY_UPDATE",
        "target": "detector_policy",
        "alert_level": 2, "event_type": "admin",
        "detail": data,
    })
    return jsonify(new_policy)


@app.route("/api/config/reload", methods=["POST"])
def config_reload():
    reloaded = []
    if api.integrity_monitor_ref:
        api.integrity_monitor_ref._load_config()
        reloaded.append("integrity")
    if api.package_monitor_ref:
        api.package_monitor_ref._load_config()
        reloaded.append("packages")
    if api.edr_detector_ref:
        api.edr_detector_ref.reload_policy()
        reloaded.append("edr_detector")
    push_event({
        "source": "ADMIN", "action": "CONFIG_RELOAD",
        "detail": f"설정 리로드: {', '.join(reloaded)}",
        "alert_level": 1, "event_type": "admin",
    })
    return jsonify({"reloaded": reloaded})
