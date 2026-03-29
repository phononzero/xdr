"""
Integrity + Package Monitor API routes.
"""

from flask import request, jsonify
import api
from api import app, push_event


@app.route("/api/integrity/status")
def integrity_status():
    if not api.integrity_monitor_ref:
        return jsonify({"error": "not initialized"}), 503
    return jsonify(api.integrity_monitor_ref.get_status())


@app.route("/api/integrity/baselines")
def integrity_baselines():
    if not api.integrity_monitor_ref:
        return jsonify([])
    return jsonify(api.integrity_monitor_ref.get_baselines())


@app.route("/api/integrity/diffs")
def integrity_diffs():
    if not api.integrity_monitor_ref:
        return jsonify([])
    return jsonify(api.integrity_monitor_ref.get_diffs())


@app.route("/api/integrity/scan", methods=["POST"])
def integrity_scan():
    if not api.integrity_monitor_ref:
        return jsonify({"error": "not initialized"}), 503
    result = api.integrity_monitor_ref.run_scan()
    push_event({
        "source": "ADMIN", "action": "INTEGRITY_SCAN",
        "target": "integrity", "alert_level": 1,
        "event_type": "admin", "detail": result,
    })
    return jsonify(result)


@app.route("/api/integrity/update-baseline", methods=["POST"])
def integrity_update():
    if not api.integrity_monitor_ref:
        return jsonify({"error": "not initialized"}), 503
    result = api.integrity_monitor_ref.initialize_baseline()
    return jsonify(result)


@app.route("/api/integrity/diff-detail/<path:filename>")
def integrity_diff_detail(filename):
    """Return full diff detail: modified files with old/new hashes."""
    if not api.integrity_monitor_ref:
        return jsonify({"error": "not initialized"}), 503
    import json as _json
    from pathlib import Path
    diff_path = Path("/opt/xdr/integrity/diffs") / filename
    if not diff_path.exists():
        return jsonify({"error": "not found"}), 404
    try:
        with open(diff_path) as f:
            data = _json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/integrity/baseline-detail/<path:filename>")
def integrity_baseline_detail(filename):
    """Return full baseline entries with all file hashes."""
    if not api.integrity_monitor_ref:
        return jsonify({"error": "not initialized"}), 503
    import json as _json
    from pathlib import Path
    bl_path = Path("/opt/xdr/integrity/baselines") / filename
    if not bl_path.exists():
        return jsonify({"error": "not found"}), 404
    try:
        with open(bl_path) as f:
            data = _json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/packages/status")
def packages_status():
    if not api.package_monitor_ref:
        return jsonify({"error": "not initialized"}), 503
    return jsonify(api.package_monitor_ref.get_status())


@app.route("/api/packages/snapshots")
def packages_snapshots():
    if not api.package_monitor_ref:
        return jsonify([])
    return jsonify(api.package_monitor_ref.get_snapshots())


@app.route("/api/packages/diffs")
def packages_diffs():
    if not api.package_monitor_ref:
        return jsonify([])
    return jsonify(api.package_monitor_ref.get_diffs())


@app.route("/api/packages/timeline")
def packages_timeline():
    if not api.package_monitor_ref:
        return jsonify([])
    return jsonify(api.package_monitor_ref.get_timeline())


@app.route("/api/packages/scan", methods=["POST"])
def packages_scan():
    if not api.package_monitor_ref:
        return jsonify({"error": "not initialized"}), 503
    result = api.package_monitor_ref.run_scan()
    push_event({
        "source": "ADMIN", "action": "PACKAGE_SCAN",
        "target": "packages", "alert_level": 1,
        "event_type": "admin", "detail": result,
    })
    return jsonify(result)
