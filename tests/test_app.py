"""
Enterprise MCP Gateway - Application Factory Unit Tests.

Covers create_app(): construction without raising, the route table, the
health/root endpoints, the mounted MCP app, and the FASTMCP_STATELESS_HTTP
toggle.

These tests are synchronous by design. pytest-asyncio is not installed, so
async tests would be collected and skipped rather than run; starlette's
TestClient drives the real ASGI app from sync code instead.
"""

import json

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

import gateway.config.db as db_module
import gateway.middleware.auth as auth_module
from gateway.app import create_app
from gateway.security.consumer_registry import ConsumerProfile

# Number of tools registered by _register_tools(), verified from the code:
# 1 built-in + 4 Jira + 4 BRE stubs + 3 Neo4j + 3 Teradata.
EXPECTED_TOOL_COUNT = 15

_MCP_HEADERS = {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
}


def _parse_sse(body: str) -> dict:
    """Extract the last JSON payload from an SSE response body."""
    payload = {}
    for line in body.split("\n"):
        line = line.strip()
        if line.startswith("data:"):
            raw = line[5:].strip()
            if raw:
                payload = json.loads(raw)
    return payload


@pytest.fixture(autouse=True)
def no_documentdb(monkeypatch):
    """Keep the tests hermetic: no DocumentDB connection attempts."""
    monkeypatch.setattr(db_module, "get_db", lambda: None)


@pytest.fixture
def valid_consumer(monkeypatch):
    """Make a single API key resolve to a full-access consumer profile."""
    profile = ConsumerProfile(
        api_key="test-key",
        consumer="test",
        type="rest-api",
        allowed_tools=["*"],
        rate_limit=30,
        projects=["*"],
    )

    def fake_authenticate(api_key):
        return profile if api_key == "test-key" else None

    monkeypatch.setattr(auth_module, "authenticate", fake_authenticate)
    return profile


# ======================================================================
# Application Factory
# ======================================================================

class TestCreateApp:
    def test_returns_starlette_app(self):
        app = create_app()
        assert isinstance(app, Starlette)

    def test_route_table(self):
        app = create_app()
        paths = [getattr(r, "path", None) for r in app.routes]
        assert "/" in paths
        assert "/health" in paths
        assert "/mcp" in paths

    def test_mcp_is_mounted(self):
        app = create_app()
        mcp_routes = [r for r in app.routes if getattr(r, "path", None) == "/mcp"]
        assert len(mcp_routes) == 1
        # A Mount exposes the child ASGI app; a plain Route does not.
        assert hasattr(mcp_routes[0], "app")

    def test_stateless_http_disabled_still_builds(self, monkeypatch):
        monkeypatch.setenv("FASTMCP_STATELESS_HTTP", "false")
        app = create_app()
        assert isinstance(app, Starlette)


# ======================================================================
# HTTP Endpoints
# ======================================================================

class TestHttpEndpoints:
    def test_health_is_public_and_healthy(self):
        with TestClient(create_app()) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            assert resp.json()["status"] == "healthy"

    def test_root_reports_endpoints(self):
        with TestClient(create_app()) as client:
            resp = client.get("/")
            assert resp.status_code == 200
            assert "endpoints" in resp.json()


# ======================================================================
# MCP Endpoint
# ======================================================================

class TestMcpEndpoint:
    def test_tools_list_returns_registered_tools(self, valid_consumer):
        with TestClient(create_app()) as client:
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={**_MCP_HEADERS, "X-MCP-API-Key": "test-key"},
            )
            assert resp.status_code == 200
            tools = _parse_sse(resp.text)["result"]["tools"]
            names = [t["name"] for t in tools]
            assert "health_status" in names
            assert len(names) == EXPECTED_TOOL_COUNT
