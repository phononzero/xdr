"""
Asset Management API routes — kernel modules, packages, hardware, policy, scanning, logs.
"""

import logging
from flask import request, jsonify
from api import app

import asset_manager
from asset_policy import get_policy
from asset_scanner import AssetScanner
from asset_logger import get_logger, EVT_ACTION, EVT_POLICY_CHANGE, EVT_MODULE_UNLOAD, EVT_MODULE_BLOCK, EVT_HW_BLOCK

logger = logging.getLogger("xdr.api.assets")

_scanner = None


def init_asset_scanner(push_event_fn=None):
    """Initialize the asset scanner (called from xdr_engine)."""
    global _scanner
    _scanner = AssetScanner(push_event_fn=push_event_fn, interval=300)
    _scanner.start()


# ═══════════════════════════════════════════════════════
# Kernel Modules
# ═══════════════════════════════════════════════════════

@app.route("/api/assets/modules")
def get_asset_modules():
    modules = asset_manager.get_loaded_modules()
    policy = get_policy()
    for m in modules:
        m["whitelisted"] = policy.is_whitelisted("modules", m["name"])
        m["blacklisted"] = policy.is_blacklisted("modules", m["name"])
    return jsonify(modules)


@app.route("/api/assets/modules/unload", methods=["POST"])
def unload_asset_module():
    data = request.get_json(force=True)
    name = data.get("name", "")
    if not name:
        return jsonify({"ok": False, "message": "모듈 이름 필요"}), 400

    result = asset_manager.unload_module(name)
    asset_log = get_logger()
    asset_log.log(EVT_MODULE_UNLOAD, "modules", name,
                  detail=f"모듈 언로드 {'성공' if result['ok'] else '실패'}",
                  result="success" if result["ok"] else "fail")
    return jsonify(result)


@app.route("/api/assets/modules/block", methods=["POST"])
def block_asset_module():
    data = request.get_json(force=True)
    name = data.get("name", "")
    if not name:
        return jsonify({"ok": False, "message": "모듈 이름 필요"}), 400

    result = asset_manager.block_module(name)
    policy = get_policy()
    policy.add_to_blacklist("modules", name)

    asset_log = get_logger()
    asset_log.log(EVT_MODULE_BLOCK, "modules", name,
                  detail="모듈 블랙리스트 추가",
                  result="success" if result["ok"] else "fail")
    return jsonify(result)


@app.route("/api/assets/modules/unblock", methods=["POST"])
def unblock_asset_module():
    data = request.get_json(force=True)
    name = data.get("name", "")
    if not name:
        return jsonify({"ok": False, "message": "모듈 이름 필요"}), 400

    result = asset_manager.unblock_module(name)
    policy = get_policy()
    policy.remove_from_list("modules", "blacklist", name)

    asset_log = get_logger()
    asset_log.log(EVT_ACTION, "modules", name,
                  detail="모듈 블랙리스트 해제")
    return jsonify(result)


# ═══════════════════════════════════════════════════════
# Packages
# ═══════════════════════════════════════════════════════

@app.route("/api/assets/packages")
def get_asset_packages():
    packages = asset_manager.get_installed_packages()
    policy = get_policy()
    for p in packages:
        p["whitelisted"] = policy.is_whitelisted("packages", p["name"])
        p["blacklisted"] = policy.is_blacklisted("packages", p["name"])
    return jsonify(packages)


# ═══════════════════════════════════════════════════════
# Hardware
# ═══════════════════════════════════════════════════════

@app.route("/api/assets/hardware")
def get_asset_hardware():
    devices = asset_manager.get_hardware_devices()
    policy = get_policy()
    for d in devices:
        name = d.get("name", "")
        dev_id = f"{d.get('vendor_id', '')}:{d.get('product_id', '')}"
        d["whitelisted"] = policy.is_whitelisted("hardware", name) or \
                           policy.is_whitelisted("hardware", dev_id)
        d["blacklisted"] = policy.is_blacklisted("hardware", name) or \
                           policy.is_blacklisted("hardware", dev_id)
    return jsonify(devices)


@app.route("/api/assets/hardware/block", methods=["POST"])
def block_asset_hardware():
    data = request.get_json(force=True)
    vendor = data.get("vendor_id", "")
    product = data.get("product_id", "")
    name = data.get("name", f"USB {vendor}:{product}")

    if not vendor or not product:
        return jsonify({"ok": False, "message": "vendor_id, product_id 필요"}), 400

    result = asset_manager.block_usb_device(vendor, product)
    policy = get_policy()
    policy.add_to_blacklist("hardware", {
        "vendor": vendor, "product": product, "name": name
    })

    asset_log = get_logger()
    asset_log.log(EVT_HW_BLOCK, "hardware", name,
                  detail=f"USB {vendor}:{product} 차단")
    return jsonify(result)


@app.route("/api/assets/hardware/unblock", methods=["POST"])
def unblock_asset_hardware():
    data = request.get_json(force=True)
    vendor = data.get("vendor_id", "")
    product = data.get("product_id", "")
    name = data.get("name", "")

    result = asset_manager.unblock_usb_device(vendor, product)
    policy = get_policy()
    policy.remove_from_list("hardware", "blacklist", name)

    asset_log = get_logger()
    asset_log.log(EVT_ACTION, "hardware", name,
                  detail=f"USB {vendor}:{product} 차단 해제")
    return jsonify(result)


# ═══════════════════════════════════════════════════════
# Policy (Whitelist/Blacklist)
# ═══════════════════════════════════════════════════════

@app.route("/api/assets/policy")
def get_asset_policy():
    return jsonify(get_policy().get_all())


@app.route("/api/assets/policy/<section>")
def get_asset_policy_section(section):
    if section not in ("modules", "packages", "hardware"):
        return jsonify({"error": "invalid section"}), 400
    return jsonify(get_policy().get_section(section))


@app.route("/api/assets/policy/add", methods=["POST"])
def add_to_policy():
    data = request.get_json(force=True)
    section = data.get("section", "")
    list_type = data.get("list_type", "")  # whitelist or blacklist
    item = data.get("item", "")

    if not all([section, list_type, item]):
        return jsonify({"ok": False, "message": "section, list_type, item 필요"}), 400
    if section not in ("modules", "packages", "hardware"):
        return jsonify({"ok": False, "message": "invalid section"}), 400
    if list_type not in ("whitelist", "blacklist"):
        return jsonify({"ok": False, "message": "invalid list_type"}), 400

    policy = get_policy()
    if list_type == "whitelist":
        result = policy.add_to_whitelist(section, item)
    else:
        result = policy.add_to_blacklist(section, item)

    asset_log = get_logger()
    asset_log.log(EVT_POLICY_CHANGE, section, str(item),
                  detail=f"{list_type}에 추가")
    return jsonify(result)


@app.route("/api/assets/policy/remove", methods=["POST"])
def remove_from_policy():
    data = request.get_json(force=True)
    section = data.get("section", "")
    list_type = data.get("list_type", "")
    item = data.get("item", "")

    if not all([section, list_type, item]):
        return jsonify({"ok": False, "message": "section, list_type, item 필요"}), 400

    result = get_policy().remove_from_list(section, list_type, item)

    asset_log = get_logger()
    asset_log.log(EVT_POLICY_CHANGE, section, str(item),
                  detail=f"{list_type}에서 제거")
    return jsonify(result)


# ═══════════════════════════════════════════════════════
# Scanning
# ═══════════════════════════════════════════════════════

@app.route("/api/assets/scan/status")
def get_scan_status():
    if _scanner:
        return jsonify(_scanner.get_last_results())
    return jsonify({})


@app.route("/api/assets/scan/trigger", methods=["POST"])
def trigger_scan():
    if _scanner:
        results = _scanner.scan_now()
        asset_log = get_logger()
        asset_log.log(EVT_ACTION, "system", "manual_scan",
                      detail="수동 스캔 실행")
        return jsonify(results)
    return jsonify({"error": "scanner not initialized"}), 500


# ═══════════════════════════════════════════════════════
# Logs
# ═══════════════════════════════════════════════════════

@app.route("/api/assets/logs")
def get_asset_logs():
    limit = request.args.get("limit", 200, type=int)
    offset = request.args.get("offset", 0, type=int)
    event_type = request.args.get("type", None)
    category = request.args.get("category", None)
    search = request.args.get("search", None)

    asset_log = get_logger()
    logs = asset_log.get_logs(limit=limit, offset=offset,
                              event_type=event_type, category=category,
                              search=search)
    return jsonify(logs)


@app.route("/api/assets/logs/stats")
def get_asset_log_stats():
    return jsonify(get_logger().get_stats())
