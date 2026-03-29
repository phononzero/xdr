"""
XDR API Authentication — JWT-based session management.

Endpoints:
  POST /api/auth/login   — Validate API secret → return JWT
  POST /api/auth/refresh — Refresh an expiring JWT
  GET  /api/auth/check   — Verify current token
  POST /api/auth/logout  — Invalidate token (client-side)

Security:
  - JWT tokens expire after 8 hours
  - Refresh allowed within 24 hours of original issue
  - Rate limiting: 5 failed attempts per IP per minute
"""

import time
import hashlib
import hmac
import logging
import os
from datetime import datetime
from collections import defaultdict
from threading import Lock

import jwt
from flask import request, jsonify
from api import app

logger = logging.getLogger("xdr.auth")

# ── Configuration ────────────────────────────────────────

JWT_ALGORITHM = "HS256"
JWT_EXPIRE_SECS = 8 * 3600      # 8 hours
JWT_REFRESH_WINDOW = 24 * 3600   # 24 hours from original issue
RATE_LIMIT_WINDOW = 60           # seconds
RATE_LIMIT_MAX = 5               # max failed attempts per window

# JWT secret key — derived from API secret for consistency
_jwt_secret: str | None = None


def _get_jwt_secret() -> str:
    global _jwt_secret
    if _jwt_secret:
        return _jwt_secret
    try:
        from api.middleware import API_SECRET
        # Derive a separate key from the API secret
        _jwt_secret = hashlib.sha256(
            f"jwt:{API_SECRET}".encode()
        ).hexdigest()
        return _jwt_secret
    except Exception:
        _jwt_secret = os.urandom(32).hex()
        return _jwt_secret


# ── Rate limiting ────────────────────────────────────────

_fail_counts: dict[str, list[float]] = defaultdict(list)
_fail_lock = Lock()


def _check_rate_limit(ip: str) -> bool:
    """Returns True if IP is rate-limited."""
    now = time.time()
    with _fail_lock:
        attempts = _fail_counts[ip]
        # Prune old entries
        attempts[:] = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
        if len(attempts) >= RATE_LIMIT_MAX:
            return True
    return False


def _record_failure(ip: str):
    now = time.time()
    with _fail_lock:
        _fail_counts[ip].append(now)


# ── Token generation ─────────────────────────────────────

def _create_token(subject: str = "xdr-user") -> dict:
    """Create a JWT token."""
    now = int(time.time())
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + JWT_EXPIRE_SECS,
        "iss": "xdr-auth",
    }
    token = jwt.encode(payload, _get_jwt_secret(), algorithm=JWT_ALGORITHM)
    return {
        "token": token,
        "expires_in": JWT_EXPIRE_SECS,
        "token_type": "Bearer",
    }


def verify_token(token: str) -> dict | None:
    """Verify a JWT token. Returns payload or None."""
    try:
        payload = jwt.decode(
            token, _get_jwt_secret(),
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "iat", "exp"]}
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ── Routes ───────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    """Authenticate with API secret and receive JWT."""
    client_ip = request.remote_addr or "unknown"

    # Rate limit check
    if _check_rate_limit(client_ip):
        return jsonify({
            "error": "Too many failed attempts. Try again later.",
            "retry_after": RATE_LIMIT_WINDOW,
        }), 429

    data = request.get_json(silent=True) or {}
    secret = data.get("secret", "")

    if not secret:
        _record_failure(client_ip)
        return jsonify({"error": "Secret required"}), 401

    # Validate against API secret
    try:
        from api.middleware import API_SECRET
        if not hmac.compare_digest(secret, API_SECRET):
            _record_failure(client_ip)
            logger.warning(f"Auth failed from {client_ip}")
            return jsonify({"error": "Invalid secret"}), 401
    except Exception:
        _record_failure(client_ip)
        return jsonify({"error": "Auth system error"}), 500

    # Success — generate JWT
    token_data = _create_token()
    logger.info(f"Auth success from {client_ip}")
    return jsonify(token_data)


@app.route("/api/auth/refresh", methods=["POST"])
def auth_refresh():
    """Refresh an expiring JWT (must still be valid)."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Token required"}), 401

    token = auth_header[7:]
    try:
        # Allow expired tokens within the refresh window
        payload = jwt.decode(
            token, _get_jwt_secret(),
            algorithms=[JWT_ALGORITHM],
            options={"verify_exp": False, "require": ["sub", "iat"]}
        )
        # Check if within refresh window
        iat = payload.get("iat", 0)
        if time.time() - iat > JWT_REFRESH_WINDOW:
            return jsonify({"error": "Token too old to refresh"}), 401

        token_data = _create_token(payload.get("sub", "xdr-user"))
        return jsonify(token_data)
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


@app.route("/api/auth/check", methods=["GET"])
def auth_check():
    """Check if current authentication is valid."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        payload = verify_token(token)
        if payload:
            return jsonify({
                "authenticated": True,
                "subject": payload.get("sub"),
                "expires": payload.get("exp"),
            })
    return jsonify({"authenticated": False}), 401


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    """Logout (client-side token discard)."""
    return jsonify({"status": "ok", "message": "Token discarded"})
