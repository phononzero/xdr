#!/usr/bin/env python3
"""
Tests for API routes — Flask test client, middleware, core endpoints.

The middleware module calls _get_api_secret() at import time (line 29),
so we must patch SECRET_FILE before importing the module.
"""

import sys
import json
import time
import hmac
import hashlib
import pytest
from pathlib import Path
from unittest.mock import MagicMock


@pytest.fixture
def api_client(tmp_path):
    """Create Flask test client — middleware already patched by conftest."""
    try:
        import api.middleware as mw
        mw.API_SECRET = "test_secret_key_for_pytest"
    except Exception:
        pytest.skip("Cannot import api.middleware (permission denied)")

    import web_dashboard  # noqa: F401 — imports all api.routes_* (registers routes)
    import api
    api.app.config['TESTING'] = True
    client = api.app.test_client()
    yield client, "test_secret_key_for_pytest"


def _make_hmac_headers(secret: str, method: str, path: str, body: str = ""):
    ts = str(int(time.time()))
    message = f"{ts}:{method}:{path}:{body}"
    sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).hexdigest()
    return {"X-XDR-Timestamp": ts, "X-XDR-Signature": sig}


class TestAPIMiddleware:
    """Tests for CORS and HMAC middleware."""

    def test_options_request_allowed(self, api_client):
        client, _ = api_client
        response = client.options("/api/status")
        assert response.status_code == 204

    def test_non_api_path_no_auth(self, api_client):
        client, _ = api_client
        response = client.get("/")
        assert response.status_code in (200, 404)

    def test_cors_headers_present(self, api_client):
        client, _ = api_client
        response = client.get("/api/status",
                              headers={"Origin": "https://127.0.0.1:29992"})
        assert "Access-Control-Allow-Origin" in response.headers


class TestCoreAPI:
    """Tests for core API endpoints."""

    def test_unauthenticated_request_rejected(self, api_client):
        """Protected endpoints must reject requests without auth."""
        client, _ = api_client
        response = client.get("/api/status")
        assert response.status_code == 401

    def test_status_endpoint(self, api_client):
        client, secret = api_client
        headers = _make_hmac_headers(secret, "GET", "/api/status")
        response = client.get("/api/status", headers=headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, dict)

    def test_events_endpoint(self, api_client):
        client, secret = api_client
        headers = _make_hmac_headers(secret, "GET", "/api/events")
        response = client.get("/api/events", headers=headers)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, (list, dict))

    def test_search_endpoint(self, api_client):
        client, secret = api_client
        headers = _make_hmac_headers(secret, "GET", "/api/events/search")
        response = client.get("/api/events/search?q=test", headers=headers)
        assert response.status_code == 200


class TestBlocklistAPI:
    """Tests for blocklist CRUD endpoints."""

    def test_get_blocklist(self, api_client):
        client, _ = api_client
        mock_store = MagicMock()
        mock_store.get_all.return_value = {
            "blocked_ips": [], "blocked_ports": [], "blocked_pids": [],
            "blocked_paths": [], "blocked_hashes": [],
            "edr_watch_ips": [], "known_macs": {},
        }
        import api
        api.blocklist_store = mock_store
        _, secret = api_client
        headers = _make_hmac_headers(secret, "GET", "/api/blocklists")
        response = client.get("/api/blocklists", headers=headers)
        assert response.status_code == 200
