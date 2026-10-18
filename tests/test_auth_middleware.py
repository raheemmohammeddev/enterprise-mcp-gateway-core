"""
Enterprise MCP Gateway - Auth Middleware Regression Tests.

Pins the three unauthenticated wildcard-admin paths that were removed:

    (i)   no credential at all (was: anonymous full-access profile)
    (ii)  unregistered API key with a 'kiro-' app name (was: kiro-passthrough)
    (iii) 'kiro-' app name with no token (was: legacy auto-whitelist)

Each must now return HTTP 401, while a configured consumer still succeeds and
public paths still bypass auth.

Also pins the pure-ASGI contract of AuthMiddleware: a chunked downstream
response is forwarded message by message rather than materialized, non-http
scopes pass through, and the caller identity reaches the downstream tool
without leaking into the next request.

These tests are synchronous by design (pytest-asyncio is not installed, so
async tests would be skipped rather than run) and drive the real ASGI app
through starlette's TestClient, which is an httpx client over the app. The two
tests that drive the middleware directly use asyncio.run() inside a sync test
for the same reason.

Monkeypatches target the names bound into gateway.middleware.auth at import
time, not gateway.config.settings.
"""

import asyncio
import json

import pytest
from starlette.testclient import TestClient

import gateway.middleware.auth as auth_module
from gateway.app import create_app
from gateway.middleware.auth import AuthMiddleware, get_current_caller
from gateway.security.consumer_registry import ConsumerProfile

_MCP_HEADERS = {
    "accept": "application/json, text/event-stream",
    "content-type": "application/json",
}
_TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


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


def _http_scope(path: str, method: str = "GET") -> dict:
    """Build a minimal ASGI http scope for driving the middleware directly."""
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
        "root_path": "",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": b"",
        "headers": [],
    }


async def _empty_receive() -> dict:
    return {"type": "http.request", "body": b"", "more_body": False}


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


# ======================================================================
# Pure ASGI Contract
# ======================================================================

class TestPureAsgiContract:
    """AuthMiddleware must not buffer the downstream response.

    BaseHTTPMiddleware rebuilt the downstream response into a single object,
    which stalls the long-lived streamable-HTTP / SSE responses served from
    /mcp. These tests drive the middleware directly so the assertion is about
    the middleware alone, not about what any particular MCP handler happens to
    emit.
    """

    def test_streaming_body_reaches_send_unbuffered(self):
        async def streaming_app(scope, receive, send):
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/event-stream")],
            })
            await send({"type": "http.response.body", "body": b"one", "more_body": True})
            await send({"type": "http.response.body", "body": b"two", "more_body": True})
            await send({"type": "http.response.body", "body": b"three"})

        sent = []

        async def capture(message):
            sent.append(message)

        # /health is a public path, so auth is bypassed and this isolates the
        # streaming behaviour from every auth decision.
        asyncio.run(
            AuthMiddleware(streaming_app)(
                _http_scope("/health"), _empty_receive, capture
            )
        )

        assert len(sent) == 4
        assert sent[0]["type"] == "http.response.start"
        assert [m["type"] for m in sent[1:]] == ["http.response.body"] * 3
        assert [m["body"] for m in sent[1:]] == [b"one", b"two", b"three"]
        assert sent[1]["more_body"] is True
        assert sent[2]["more_body"] is True
        assert sent[3].get("more_body", False) is False

    def test_non_http_scope_passes_through(self):
        seen = []

        async def inner(scope, receive, send):
            seen.append(scope["type"])

        async def lifespan_receive():
            return {"type": "lifespan.startup"}

        async def lifespan_send(message):
            seen.append(message["type"])

        asyncio.run(
            AuthMiddleware(inner)({"type": "lifespan"}, lifespan_receive, lifespan_send)
        )

        assert seen == ["lifespan"]


# ======================================================================
# Identity Propagation and Isolation
# ======================================================================

class TestIdentityPropagation:
    def test_downstream_tool_sees_the_middleware_identity(self, monkeypatch):
        """The tool handler reads the caller from the ContextVar.

        A consumer scoped to one Jira tool calls health_status; the
        tool_authorization guardrail can only deny it if the handler, running
        inside the mounted MCP app, saw the identity this middleware set.
        """
        profile = ConsumerProfile(
            api_key="scoped-key",
            consumer="scoped",
            type="rest-api",
            allowed_tools=["get_jira_issues"],
            rate_limit=30,
            projects=["*"],
        )
        monkeypatch.setattr(
            auth_module,
            "authenticate",
            lambda api_key: profile if api_key == "scoped-key" else None,
        )

        with TestClient(create_app()) as client:
            resp = client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/call",
                    "params": {"name": "health_status", "arguments": {}},
                },
                headers={**_MCP_HEADERS, "X-MCP-API-Key": "scoped-key"},
            )
            assert resp.status_code == 200
            result = _parse_sse(resp.text)["result"]["structuredContent"]
            assert result["error"] == "forbidden"
            assert result["guardrail"] == "tool_authorization"

    def test_caller_does_not_leak_between_requests(self, client_factory):
        """Two sequential callers; the ContextVar is reset after each response."""
        with client_factory() as client:
            for user_id in ("user-one", "user-two"):
                resp = client.post(
                    "/mcp",
                    json=_TOOLS_LIST,
                    headers={
                        **_MCP_HEADERS,
                        "X-MCP-API-Key": "test-key",
                        "X-MCP-User-Id": user_id,
                    },
                )
                assert resp.status_code == 200
                assert get_current_caller() is None
