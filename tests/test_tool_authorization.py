"""
Enterprise MCP Gateway - Tool Authorization and Rate-Limit Regression Tests.

Pins three fixes:

    1. enforce_guardrails() now runs inside every registered tool, not just
       the Jira ones, so a consumer whose allowed_tools excludes a Neo4j,
       BRE or Teradata tool is denied.
    2. The X-MCP-Jira-PAT rate-limit exemption is gone: a 'request_header'
       credential source no longer disables rate limiting.
    3. A tool call with no caller identity in the context (every stdio call,
       since AuthMiddleware never runs there) is denied instead of receiving
       an implicit wildcard scope. GATEWAY_STDIO_TRUST_LOCAL is the explicit
       opt-in that restores the old behaviour.

Synchronous by design (pytest-asyncio is not installed).
"""

import time

import pytest

import gateway.backends.neo4j_backend as neo4j_module
import gateway.backends.teradata_backend as teradata_module
import gateway.config.db as db_module
import gateway.guardrails.pipeline as pipeline_module
import gateway.middleware.auth as auth_module
from gateway.backends.bre_backend import bre_search
from gateway.backends.neo4j_backend import neo4j_run_query
from gateway.backends.teradata_backend import teradata_list_databases
from gateway.config.settings import RATE_LIMIT_BRE
from gateway.guardrails.pipeline import caller_guardrail_scope
from gateway.middleware.auth import CallerIdentity
from gateway.ratelimit.limiter import _call_timestamps, _consumer_timestamps
from gateway.security.consumer_registry import ConsumerProfile


@pytest.fixture(autouse=True)
def no_documentdb(monkeypatch):
    """Keep the tests hermetic: no DocumentDB connection attempts."""
    monkeypatch.setattr(db_module, "get_db", lambda: None)


@pytest.fixture(autouse=True)
def clear_rate_state():
    """Clear all rate-limit state between tests."""
    _consumer_timestamps.clear()
    _call_timestamps.clear()
    yield
    _consumer_timestamps.clear()
    _call_timestamps.clear()


def _set_caller(allowed_tools, pat_source="server_config"):
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
    tokens = [
        auth_module._current_caller_var.set(caller),
        auth_module._jira_pat_source_var.set(pat_source),
    ]
    return tokens


def _reset_caller(tokens):
    auth_module._current_caller_var.reset(tokens[0])
    auth_module._jira_pat_source_var.reset(tokens[1])


@pytest.fixture
def scoped_caller():
    """Caller authorized for a single Jira tool and nothing else."""
    tokens = _set_caller(["jira_create_issue"])
    yield
    _reset_caller(tokens)


@pytest.fixture
def wildcard_caller():
    tokens = _set_caller(["*"])
    yield
    _reset_caller(tokens)


@pytest.fixture
def pat_header_caller():
    """Wildcard caller presenting a request-header credential source."""
    tokens = _set_caller(["*"], pat_source="request_header")
    yield
    _reset_caller(tokens)


# ======================================================================
# Guardrail Coverage Across Backends
# ======================================================================

class TestUnauthorizedToolIsDenied:
    def test_neo4j_run_query_denied(self, scoped_caller):
        result = neo4j_run_query("MATCH (n) RETURN n")
        assert result["error"] == "forbidden"
        assert result["guardrail"] == "tool_authorization"

    def test_bre_search_denied(self, scoped_caller):
        result = bre_search("x")
        assert result["error"] == "forbidden"
        assert result["guardrail"] == "tool_authorization"

    def test_teradata_list_databases_denied(self, scoped_caller):
        result = teradata_list_databases()
        assert result["error"] == "forbidden"
        assert result["guardrail"] == "tool_authorization"

    def test_disabled_backend_does_not_leak_before_authorization(
        self, scoped_caller, monkeypatch
    ):
        """Authorization decides first; enablement state stays undisclosed."""
        monkeypatch.setattr(neo4j_module, "NEO4J_ENABLED", False)
        monkeypatch.setattr(teradata_module, "TERADATA_MCP_ENABLED", False)

        assert neo4j_run_query("MATCH (n) RETURN n")["error"] == "forbidden"
        assert teradata_list_databases()["error"] == "forbidden"


class TestAuthorizedToolPasses:
    def test_bre_search_reaches_stub_payload(self, wildcard_caller):
        result = bre_search("x")
        assert result.get("error") is None
        assert result["query"] == "x"
        assert result["results"] == []


# ======================================================================
# Missing Caller Identity
# ======================================================================

class TestMissingIdentityIsDenied:
    """No CallerIdentity in the context is never a wildcard grant."""

    def test_neo4j_run_query_denied(self):
        result = neo4j_run_query("MATCH (n) RETURN n")
        assert result["error"] == "forbidden"
        assert result["guardrail"] == "tool_authorization"

    def test_bre_search_denied(self):
        result = bre_search("x")
        assert result["error"] == "forbidden"
        assert result["guardrail"] == "tool_authorization"

    def test_teradata_list_databases_denied(self):
        result = teradata_list_databases()
        assert result["error"] == "forbidden"
        assert result["guardrail"] == "tool_authorization"

    def test_scope_is_empty_not_wildcard(self):
        scope = caller_guardrail_scope()
        assert scope["allowed_tools"] == []
        assert scope["projects"] == []

    def test_stdio_trust_opt_in_restores_scope(self, monkeypatch):
        """The explicit opt-in is the only way back to unrestricted scope."""
        monkeypatch.setattr(pipeline_module, "GATEWAY_STDIO_TRUST_LOCAL", True)

        result = bre_search("x")
        assert result.get("error") is None
        assert result["query"] == "x"


# ======================================================================
# Rate-Limit Bypass Removal
# ======================================================================

class TestNoCredentialBypass:
    def test_request_header_pat_does_not_disable_rate_limiting(self, pat_header_caller):
        # Fill the global 'bre' group window to its configured limit.
        now = time.time()
        _call_timestamps["bre"] = [now for _ in range(RATE_LIMIT_BRE)]

        result = bre_search("x")
        assert result["error"] == "rate_limited"
        assert result["limit_type"] == "global"
