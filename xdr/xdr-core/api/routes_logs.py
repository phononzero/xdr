"""
Event log query API routes.
"""

import os
import sys
from flask import request, jsonify
from api import app


def _get_store():
    """Get event store, ensuring import path is correct."""
    _core_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _core_dir not in sys.path:
        sys.path.insert(0, _core_dir)
    from event_store import get_event_store
    return get_event_store()


@app.route("/api/logs")
def get_logs():
    """Query persisted events with filters."""
    store = _get_store()

    limit = min(int(request.args.get("limit", 100)), 2000)
    offset = int(request.args.get("offset", 0))
    level_min = request.args.get("level")
    source = request.args.get("source")
    since = request.args.get("since")
    until = request.args.get("until")
    search = request.args.get("q")

    events = store.query(
        limit=limit, offset=offset,
        level_min=int(level_min) if level_min else None,
        source=source, since=since, until=until, search=search,
    )
    total = store.count(
        level_min=int(level_min) if level_min else None,
        source=source,
    )
    return jsonify({"events": events, "total": total, "limit": limit, "offset": offset})


@app.route("/api/logs/stats")
def log_stats():
    """Get event count statistics."""
    store = _get_store()
    return jsonify({
        "total": store.count(),
        "critical": store.count(level_min=3),
        "warning": store.count(level_min=2),
    })
