"""
SPA (Single Page Application) serving for React dashboard.
"""

from pathlib import Path
from flask import send_from_directory, request, jsonify
from api import app

REACT_DIST = Path("/opt/xdr/dashboard/dist")


@app.route("/")
def index():
    dist_index = REACT_DIST / "index.html"
    if dist_index.exists():
        return send_from_directory(str(REACT_DIST), "index.html")
    return send_from_directory(app.static_folder, "index.html")


@app.route("/assets/<path:filename>")
def react_assets(filename):
    return send_from_directory(str(REACT_DIST / "assets"), filename)


@app.errorhandler(404)
def spa_fallback(e):
    dist_index = REACT_DIST / "index.html"
    if dist_index.exists() and not request.path.startswith("/api/"):
        return send_from_directory(str(REACT_DIST), "index.html")
    return jsonify({"error": "Not found"}), 404
