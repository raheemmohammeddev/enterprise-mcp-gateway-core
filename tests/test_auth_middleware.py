"""
Enterprise MCP Gateway - Auth Middleware Regression Tests.

Pins the three unauthenticated wildcard-admin paths that were removed:

    (i)   no credential at all (was: anonymous full-access profile)
    (ii)  unregistered API key with a 'kiro-' app name (was: kiro-passthrough)
    (iii) 'kiro-' app name with no token (was: legacy auto-whitelist)

Each must now return HTTP 401, while a configured consumer still succeeds and
public paths still bypass auth.

These tests are synchronous by design (pytest-asyncio is not installed, so
async tests would be skipped rather than run) and drive the real ASGI app
through starlette's TestClient, which is an httpx client over the app.

Monkeypatches target the names bound into gateway.middleware.auth at import
time, not gateway.config.settings.
"""

import pytest
from starlette.testclient import TestClient

import gateway.middleware.auth as auth_module
from gateway.app import create_app
from gateway.security.consumer_registry import ConsumerProfile

_MCP_HEADERS = {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
}
_TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


@pytest.fixture
def client_factory(monkeypatch):
    """Build TestClients over the real app with a known consumer registry."""
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
    app = create_app()

    def make(client=None):
        if client is None:
            return TestClient(app)
        return TestClient(app, client=client)

    return make


# ======================================================================
# Removed Bypass Paths
# ======================================================================

class TestBypassRegressions:
    def test_no_api_key_is_unauthorized(self, client_factory):
        """Path C: authenticate(None) no longer grants a wildcard profile."""
        with client_factory() as client:
            resp = client.post("/mcp", json=_TOOLS_LIST, headers=_MCP_HEADERS)
            assert resp.status_code == 401
            assert resp.json()["error"] == "unauthorized"

    def test_unregistered_key_with_kiro_app_name_is_unauthorized(self, client_factory):
        """Path B: the kiro- prefix no longer waives API-key registration."""
        with client_factory() as client:
            resp = client.post(
                "/mcp",
                json=_TOOLS_LIST,
                headers={
                    **_MCP_HEADERS,
                    "X-MCP-API-Key": "bogus-key-not-in-registry",
                    "X-MCP-App-Name": "kiro-test",
                },
            )
            assert resp.status_code == 401
            assert resp.json()["error"] == "unauthorized"

    def test_legacy_auto_whitelist_is_unauthorized(self, client_factory):
        """Path A: a kiro- app name with no token is rejected by default."""
        with client_factory() as client:
            resp = client.post(
                "/mcp",
                json=_TOOLS_LIST,
                headers={**_MCP_HEADERS, "X-MCP-App-Name": "kiro-local"},
            )
            assert resp.status_code == 401
            assert resp.json()["error"] == "kiro_auth_required"

    def test_invalid_kiro_token_is_unauthorized(self, client_factory):
        with client_factory() as client:
            resp = client.post(
                "/mcp",
                json=_TOOLS_LIST,
                headers={
                    **_MCP_HEADERS,
                    "X-MCP-App-Name": "kiro-local",
                    "X-MCP-Auth-Token": "not-a-real-token",
                },
            )
            assert resp.status_code == 401
            assert resp.json()["error"] == "kiro_token_invalid"


# ======================================================================
# Positive Controls
# ======================================================================

class TestAuthorizedAccess:
    def test_configured_consumer_succeeds(self, client_factory):
        with client_factory() as client:
            resp = client.post(
                "/mcp",
                json=_TOOLS_LIST,
                headers={**_MCP_HEADERS, "X-MCP-API-Key": "test-key"},
            )
            assert resp.status_code == 200

    def test_health_bypasses_auth(self, client_factory):
        with client_factory() as client:
            assert client.get("/health").status_code == 200


# ======================================================================
# Opt-In Local Escape Hatch
# ======================================================================

class TestInsecureLocalOptIn:
    def test_non_loopback_peer_still_unauthorized(self, client_factory, monkeypatch):
        """Opting in is not enough: the peer must be loopback."""
        monkeypatch.setattr(auth_module, "GATEWAY_ALLOW_INSECURE_LOCAL", True)
        monkeypatch.setattr(auth_module, "KIRO_RBAC_ENABLED", False)

        # The default TestClient peer address is 'testclient', not loopback.
        with client_factory() as client:
            resp = client.post(
                "/mcp",
                json=_TOOLS_LIST,
                headers={**_MCP_HEADERS, "X-MCP-App-Name": "kiro-local"},
            )
            assert resp.status_code == 401

    def test_loopback_peer_with_opt_in_succeeds(self, client_factory, monkeypatch):
        monkeypatch.setattr(auth_module, "GATEWAY_ALLOW_INSECURE_LOCAL", True)
        monkeypatch.setattr(auth_module, "KIRO_RBAC_ENABLED", False)

        with client_factory(client=("127.0.0.1", 12345)) as client:
            resp = client.post(
                "/mcp",
                json=_TOOLS_LIST,
                headers={**_MCP_HEADERS, "X-MCP-App-Name": "kiro-local"},
            )
            assert resp.status_code == 200

    def test_forwarded_loopback_peer_is_unauthorized(self, client_factory, monkeypatch):
        """A proxied request is refused even when the peer looks loopback."""
        monkeypatch.setattr(auth_module, "GATEWAY_ALLOW_INSECURE_LOCAL", True)
        monkeypatch.setattr(auth_module, "KIRO_RBAC_ENABLED", False)

        with client_factory(client=("127.0.0.1", 12345)) as client:
            resp = client.post(
                "/mcp",
                json=_TOOLS_LIST,
                headers={
                    **_MCP_HEADERS,
                    "X-MCP-App-Name": "kiro-local",
                    "X-Forwarded-For": "203.0.113.10",
                },
            )
            assert resp.status_code == 401
            assert resp.json()["error"] == "kiro_auth_required"

    def test_loopback_peer_without_opt_in_is_unauthorized(self, client_factory, monkeypatch):
        monkeypatch.setattr(auth_module, "KIRO_RBAC_ENABLED", False)

        with client_factory(client=("127.0.0.1", 12345)) as client:
            resp = client.post(
                "/mcp",
                json=_TOOLS_LIST,
                headers={**_MCP_HEADERS, "X-MCP-App-Name": "kiro-local"},
            )
            assert resp.status_code == 401
