"""
CORS + Authentication middleware (HMAC + JWT).

Auth flow:
  1. OPTIONS → always allowed (CORS preflight)
  2. Non-API paths (/, /assets/*) → allowed (SPA serving)
  3. /api/stream (SSE) → allowed (no auth for EventSource)
  4. /api/auth/* → allowed (login/refresh endpoints)
  5. All other /api/* → require JWT Bearer token OR HMAC signature
"""

import time
import hmac
import hashlib
import os
import logging
from pathlib import Path

from flask import request, Response, jsonify
from api import app

# ── HMAC API Secret ──────────────────────────────────────
SECRET_FILE = Path("/opt/xdr/xdr-core/.api_secret")


def _get_api_secret() -> str:
    if SECRET_FILE.exists():
        return SECRET_FILE.read_text().strip()
    secret = os.urandom(32).hex()
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    SECRET_FILE.write_text(secret)
    SECRET_FILE.chmod(0o600)
    return secret


API_SECRET = _get_api_secret()

# Auth-exempt paths
AUTH_EXEMPT = {"/api/auth/login", "/api/auth/logout", "/api/stream"}


@app.after_request
def add_cors(response):
    origin = request.headers.get('Origin', '')
    allowed = ['https://127.0.0.1:29993', 'https://localhost:29993',
               'http://127.0.0.1:29993', 'http://localhost:29993',
               'https://127.0.0.1:29992', 'https://localhost:29992',
               'http://127.0.0.1:29992', 'http://localhost:29992']
    if origin in allowed:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = (
            'Content-Type, X-XDR-Timestamp, X-XDR-Signature, Authorization'
        )
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


@app.before_request
def check_auth():
    # 1. CORS preflight
    if request.method == 'OPTIONS':
        return Response('', 204)

    # 2. Non-API paths (SPA)
    if not request.path.startswith('/api/'):
        return None

    # 3. Auth-exempt endpoints
    if request.path in AUTH_EXEMPT:
        return None

    # 4. Try JWT Bearer token
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        try:
            from api.auth import verify_token
            payload = verify_token(token)
            if payload:
                return None  # Authenticated via JWT
        except Exception:
            pass

    # 5. Try HMAC signature
    sig = request.headers.get('X-XDR-Signature')
    ts = request.headers.get('X-XDR-Timestamp')
    if sig and ts:
        try:
            req_time = int(ts)
            if abs(time.time() - req_time) > 300:
                return jsonify({"error": "Request expired"}), 403
        except ValueError:
            return jsonify({"error": "Invalid timestamp"}), 403
        body = request.get_data(as_text=True) or ''
        message = f"{ts}:{request.method}:{request.path}:{body}"
        expected = hmac.new(API_SECRET.encode(), message.encode(),
                           hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            return None  # Authenticated via HMAC

    # 6. No valid auth — reject
    return jsonify({"error": "Authentication required"}), 401


# Suppress Flask request logging noise
flask_log = logging.getLogger("werkzeug")
flask_log.setLevel(logging.WARNING)
