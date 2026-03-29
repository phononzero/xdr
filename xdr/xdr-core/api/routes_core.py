"""
Core API routes — SSE stream, events, stats, status.
"""

import json
import subprocess
import logging
from queue import Queue, Empty

from flask import Response, request, jsonify
from api import app, event_history, event_history_lock, sse_queues, sse_lock


@app.route("/api/stream")
def event_stream():
    q = Queue(maxsize=200)
    with sse_lock:
        sse_queues.append(q)

    def generate():
        try:
            while True:
                try:
                    data = q.get(timeout=30)
                    yield f"data: {data}\n\n"
                except Empty:
                    yield ": keepalive\n\n"
        except GeneratorExit:
            with sse_lock:
                if q in sse_queues:
                    sse_queues.remove(q)

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/api/events")
def get_events():
    limit = request.args.get("limit", 100, type=int)
    level = request.args.get("level", 0, type=int)
    with event_history_lock:
        filtered = event_history if level == 0 else [
            e for e in event_history if e.get("alert_level", 0) >= level
        ]
        return jsonify(filtered[-limit:])


@app.route("/api/stats")
def get_stats():
    stats = {"total": 0, "passed": 0, "dropped": 0, "alerts": 0}
    try:
        result = subprocess.run(
            ["bpftool", "map", "dump", "name", "pkt_stats", "-j"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            labels = {0: "total", 1: "passed", 2: "dropped", 3: "alerts"}
            for entry in data:
                key = entry.get("key", 0)
                values = entry.get("values", [])
                total_val = sum(v.get("value", 0) for v in values) if values else entry.get("value", 0)
                if key in labels:
                    stats[labels[key]] = total_val
    except Exception as e:
        logging.debug(f"Stats fetch error: {e}")

    with event_history_lock:
        stats["event_count"] = len(event_history)
        stats["critical_count"] = sum(
            1 for e in event_history if e.get("alert_level", 0) >= 3
        )
        stats["warning_count"] = sum(
            1 for e in event_history if e.get("alert_level", 0) == 2
        )

    return jsonify(stats)


@app.route("/api/status")
def get_status():
    import os
    from pathlib import Path

    status = {
        "engine": "running",
        "edr_loaded": False,
        "ndr_attached": False,
        "uptime": None,
        "kernel": None,
    }

    try:
        status["kernel"] = os.uname().release
    except Exception:
        pass

    edr_pins = Path("/sys/fs/bpf/xdr_edr")
    status["edr_loaded"] = edr_pins.exists() and any(edr_pins.iterdir())

    try:
        result = subprocess.run(
            ["ip", "link", "show", "enp4s0"],
            capture_output=True, text=True, timeout=3
        )
        status["ndr_attached"] = "xdp" in result.stdout.lower()
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["systemctl", "show", "xdr.service", "--property=ActiveEnterTimestamp"],
            capture_output=True, text=True, timeout=3
        )
        ts = result.stdout.strip().split("=", 1)[1] if "=" in result.stdout else ""
        if ts:
            status["uptime"] = ts
    except Exception:
        pass

    return jsonify(status)


@app.route("/api/events/search")
def search_events():
    q = request.args.get("q", "").lower()
    source = request.args.get("source", "").upper()
    level = request.args.get("level", 0, type=int)
    limit = min(request.args.get("limit", 100, type=int), 500)

    with event_history_lock:
        results = []
        for ev in reversed(event_history):
            if len(results) >= limit:
                break
            if source and ev.get("source", "") != source:
                continue
            if level and ev.get("alert_level", 0) < level:
                continue
            if q:
                ev_str = json.dumps(ev, ensure_ascii=False).lower()
                if q not in ev_str:
                    continue
            results.append(ev)
    return jsonify(results)


@app.route("/api/debug")
def debug_info():
    import api
    engine = api._xdr_engine_ref
    info = {"engine_ref": engine is not None}
    if engine:
        rb = engine.rb_poller
        info["rb_poller"] = rb is not None
        if rb:
            info["rb_lib"] = rb._lib is not None
            info["rb_handle"] = rb._rb is not None
        info["conn_cache_size"] = len(engine.conn_cache)
        info["proc_cache_size"] = len(engine.proc_cache)
        info["edr_event_count"] = engine._edr_event_count
        info["ndr_event_count"] = engine._ndr_event_count
        info["edr_errors"] = engine._edr_errors[-5:] if engine._edr_errors else []
        info["poll_count"] = engine._poll_count
    return jsonify(info)
