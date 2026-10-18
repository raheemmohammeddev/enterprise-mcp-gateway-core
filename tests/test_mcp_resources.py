"""
Enterprise MCP Gateway - MCP Resource and Prompt Tests.

Pins the one resource (graph://neo4j/schema) and the one prompt
(cypher_query_guidance) the gateway advertises:

    1. Both run the guardrail pipeline before any driver work, so a caller
       denied neo4j_get_schema cannot read the resource and a caller with no
       identity is denied outright.
    2. The resource reports connected relationship patterns read from
       db.schema.visualization(), and degrades to an empty list plus an
       explanatory note rather than fabricating patterns.
    3. resources/list and prompts/list over /mcp return the registered
       entries, and a resource is never counted as a tool.

Synchronous by design (pytest-asyncio is not installed); no live Neo4j is
reachable, so the driver is stubbed.
"""

import json

import pytest
from starlette.testclient import TestClient

import gateway.backends.neo4j_backend as neo4j_module
import gateway.config.db as db_module
import gateway.middleware.auth as auth_module
from gateway.app import create_app
from gateway.backends.neo4j_backend import (
    CYPHER_PROMPT_NAME,
    SCHEMA_RESOURCE_URI,
    cypher_query_guidance,
    neo4j_schema_resource,
)
from gateway.middleware.auth import CallerIdentity
from gateway.security.consumer_registry import ConsumerProfile
from tests.test_app import EXPECTED_TOOL_COUNT

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


def _set_caller(allowed_tools):
    """Install a caller identity in the auth context vars."""
    caller = CallerIdentity(
        app_name="test-app",
        user_id="tester",
        consumer=ConsumerProfile(
            api_key="test-key",
            consumer="test-consumer",
            type="rest-api",
            allowed_tools=allowed_tools,
            rate_limit=100,
            projects=["*"],
        ),
    )
    return auth_module._current_caller_var.set(caller)


@pytest.fixture
def scoped_caller():
    """Caller authorized for a single Jira tool and nothing else."""
    token = _set_caller(["get_jira_issues"])
    yield
    auth_module._current_caller_var.reset(token)


@pytest.fixture
def wildcard_caller():
    token = _set_caller(["*"])
    yield
    auth_module._current_caller_var.reset(token)


# ======================================================================
# Stubbed Neo4j Driver
# ======================================================================

class _FakeNode:
    def __init__(self, label):
        self.labels = frozenset([label])


class _FakeRelationship:
    def __init__(self, start, rel_type, end):
        self.start_node = _FakeNode(start)
        self.type = rel_type
        self.end_node = _FakeNode(end)


class _FakeSession:
    """Answers the four introspection queries the resource issues."""

    def __init__(self, visualization_error=None):
        self._visualization_error = visualization_error

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def run(self, query, **kwargs):
        if query == "CALL db.labels()":
            return [{"label": "Service"}, {"label": "Owner"}]
        if query == "CALL db.relationshipTypes()":
            return [{"relationshipType": "OWNED_BY"}]
        if query == "CALL db.propertyKeys()":
            return [{"propertyKey": "name"}]
        if query == neo4j_module._SCHEMA_VISUALIZATION:
            if self._visualization_error:
                raise RuntimeError(self._visualization_error)
            return [{"relationships": [_FakeRelationship("Service", "OWNED_BY", "Owner")]}]
        raise AssertionError("unexpected query: %s" % query)


class _FakeDriver:
    def __init__(self, visualization_error=None):
        self._visualization_error = visualization_error
        self.closed = False

    def session(self):
        return _FakeSession(self._visualization_error)

    def close(self):
        self.closed = True


@pytest.fixture
def fake_driver(monkeypatch):
    driver = _FakeDriver()
    monkeypatch.setattr(neo4j_module, "_get_driver", lambda: driver)
    return driver


# ======================================================================
# Authorization
# ======================================================================

class TestUnauthorizedCallerIsDenied:
    """A caller denied the equivalent tool is denied the resource and prompt."""

    def test_resource_denied(self, scoped_caller):
        result = neo4j_schema_resource()
        assert result["error"] == "forbidden"
        assert result["guardrail"] == "tool_authorization"

    def test_prompt_denied(self, scoped_caller):
        result = cypher_query_guidance("which services exist?")
        assert result["error"] == "forbidden"
        assert result["guardrail"] == "tool_authorization"

    def test_resource_does_not_touch_the_driver(self, scoped_caller, monkeypatch):
        """Authorization decides before any connection attempt."""
        def _boom():
            raise AssertionError("_get_driver() must not be reached")

        monkeypatch.setattr(neo4j_module, "_get_driver", _boom)
        assert neo4j_schema_resource()["error"] == "forbidden"


class TestMissingIdentityIsDenied:
    """No CallerIdentity in the context is never a wildcard grant."""

    def test_resource_denied(self):
        result = neo4j_schema_resource()
        assert result["error"] == "forbidden"
        assert result["guardrail"] == "tool_authorization"

    def test_prompt_denied(self):
        result = cypher_query_guidance("which services exist?")
        assert result["error"] == "forbidden"
        assert result["guardrail"] == "tool_authorization"


# ======================================================================
# Resource Payload
# ======================================================================

class TestSchemaResourcePayload:
    def test_relationship_patterns_are_connected(self, wildcard_caller, fake_driver):
        result = neo4j_schema_resource()

        assert result["labels"] == ["Service", "Owner"]
        assert result["relationship_types"] == ["OWNED_BY"]
        assert result["property_keys"] == ["name"]
        assert result["relationship_patterns"] == [
            {"start": "Service", "type": "OWNED_BY", "end": "Owner"}
        ]
        assert result["notes"] == ""
        assert fake_driver.closed is True

    def test_visualization_failure_degrades_without_fabricating(
        self, wildcard_caller, monkeypatch
    ):
        driver = _FakeDriver(visualization_error="no procedure db.schema.visualization")
        monkeypatch.setattr(neo4j_module, "_get_driver", lambda: driver)

        result = neo4j_schema_resource()

        assert result["relationship_patterns"] == []
        assert "db.schema.visualization" in result["notes"]
        assert result["labels"] == ["Service", "Owner"]

    def test_disabled_backend_does_not_leak_before_authorization(self, monkeypatch):
        monkeypatch.setattr(neo4j_module, "NEO4J_ENABLED", False)
        assert neo4j_schema_resource()["error"] == "forbidden"


# ======================================================================
# Prompt Text
# ======================================================================

class TestCypherPrompt:
    def test_prompt_embeds_schema_and_constraints(self, wildcard_caller, fake_driver):
        text = cypher_query_guidance("which services exist?")

        assert "which services exist?" in text
        assert "(:Service)-[:OWNED_BY]->(:Owner)" in text
        assert "read-only" in text
        assert "CALL dbms" in text
        assert "500" in text

    def test_prompt_withholds_schema_without_schema_authorization(
        self, monkeypatch, fake_driver
    ):
        """Graph data is only embedded for a caller who may read it."""
        token = _set_caller(["neo4j_validate_query"])
        try:
            text = cypher_query_guidance("which services exist?")
        finally:
            auth_module._current_caller_var.reset(token)

        assert "Live schema withheld" in text
        assert "OWNED_BY" not in text
        assert "read-only" in text


# ======================================================================
# Advertised Capabilities Over /mcp
# ======================================================================

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


def _rpc(client, method):
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method},
        headers={**_MCP_HEADERS, "X-MCP-API-Key": "test-key"},
    )
    assert resp.status_code == 200
    return _parse_sse(resp.text)["result"]


class TestAdvertisedCapabilities:
    def test_resources_list_returns_the_schema_resource(self, valid_consumer):
        with TestClient(create_app()) as client:
            uris = [str(r["uri"]) for r in _rpc(client, "resources/list")["resources"]]
        assert uris == [SCHEMA_RESOURCE_URI]

    def test_prompts_list_returns_the_cypher_prompt(self, valid_consumer):
        with TestClient(create_app()) as client:
            names = [p["name"] for p in _rpc(client, "prompts/list")["prompts"]]
        assert names == [CYPHER_PROMPT_NAME]

    def test_resource_and_prompt_are_not_counted_as_tools(self, valid_consumer):
        with TestClient(create_app()) as client:
            names = [t["name"] for t in _rpc(client, "tools/list")["tools"]]

        assert len(names) == EXPECTED_TOOL_COUNT
        assert "neo4j_schema_resource" not in names
        assert CYPHER_PROMPT_NAME not in names
