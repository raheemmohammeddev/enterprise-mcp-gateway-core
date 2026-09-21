"""
Enterprise MCP Gateway - Guardrail Pipeline Unit Tests.

Tests the 7-step composable security guardrail pipeline with coverage
for pass/block scenarios on each individual check and the orchestrator.
"""

import pytest

from gateway.guardrails.pipeline import (
    check_project_scope,
    check_tool_active,
    check_tool_authorization,
    check_user_write_authorization,
    check_write_credential_attribution,
    check_write_rate_limit,
    enforce_guardrails,
    validate_jql_input,
    validate_sql_readonly,
)


# ======================================================================
# Guardrail 0: Tool Active Check
# ======================================================================

class TestToolActiveCheck:
    def test_allows_by_default(self):
        """Default implementation allows all tools (fail-open)."""
        assert check_tool_active("any_tool") is None


# ======================================================================
# Guardrail 1: Tool Authorization
# ======================================================================

class TestToolAuthorization:
    def test_wildcard_allows_all(self):
        assert check_tool_authorization("jira_create_issue", ["*"]) is None

    def test_exact_match_allows(self):
        assert check_tool_authorization("jira_create_issue", ["jira_create_issue", "jira_get_issue_details"]) is None

    def test_missing_tool_blocks(self):
        result = check_tool_authorization("jira_create_issue", ["neo4j_run_query"])
        assert result is not None
        assert result["error"] == "forbidden"
        assert result["guardrail"] == "tool_authorization"

    def test_empty_list_blocks(self):
        result = check_tool_authorization("jira_create_issue", [])
        assert result is not None
        assert result["error"] == "forbidden"


# ======================================================================
# Guardrail 2: User Write Authorization
# ======================================================================

class TestUserWriteAuthorization:
    def test_non_write_tool_passes(self):
        """Read tools always pass write auth."""
        assert check_user_write_authorization("get_jira_issues", [], "ai-agent") is None

    def test_non_agent_passes(self):
        """Non-ai-agent consumers skip write auth check."""
        assert check_user_write_authorization("jira_create_issue", [], "developer") is None

    def test_matching_group_passes(self):
        result = check_user_write_authorization(
            "jira_create_issue",
            ["Platform-Admin", "Other-Group"],
            "ai-agent",
        )
        assert result is None

    def test_no_matching_group_blocks(self):
        result = check_user_write_authorization(
            "jira_create_issue",
            ["Unrelated-Group"],
            "ai-agent",
        )
        assert result is not None
        assert result["guardrail"] == "user_write_auth"

    def test_case_insensitive_matching(self):
        result = check_user_write_authorization(
            "jira_create_issue",
            ["platform-admin"],  # lowercase
            "ai-agent",
        )
        assert result is None  # Should match Platform-Admin case-insensitively


# ======================================================================
# Guardrail 3: Write Credential Attribution
# ======================================================================

class TestWriteCredentialAttribution:
    def test_user_pat_passes(self):
        assert check_write_credential_attribution("jira_create_issue", "request_header", "ai-agent") is None

    def test_profile_pat_passes(self):
        assert check_write_credential_attribution("jira_create_issue", "profile", "ai-agent") is None

    def test_server_config_blocks(self):
        result = check_write_credential_attribution("jira_create_issue", "server_config", "ai-agent")
        assert result is not None
        assert result["guardrail"] == "write_credential_attribution"

    def test_read_tool_passes(self):
        assert check_write_credential_attribution("get_jira_issues", "server_config", "ai-agent") is None

    def test_non_agent_passes(self):
        assert check_write_credential_attribution("jira_create_issue", "server_config", "developer") is None


# ======================================================================
# Guardrail 4: JQL Input Validation
# ======================================================================

class TestJqlValidation:
    def test_clean_jql_passes(self):
        assert validate_jql_input("get_jira_issues", "project = PROJ AND status = Open") is None

    def test_empty_jql_passes(self):
        assert validate_jql_input("get_jira_issues", "") is None

    def test_semicolon_drop_blocks(self):
        result = validate_jql_input("get_jira_issues", "project = PROJ; DROP TABLE users")
        assert result is not None
        assert result["guardrail"] == "input_validation"

    def test_comment_injection_blocks(self):
        result = validate_jql_input("get_jira_issues", "project = PROJ -- comment")
        assert result is not None

    def test_block_comment_injection_blocks(self):
        result = validate_jql_input("get_jira_issues", "project = PROJ /* bypass */ AND 1=1")
        assert result is not None

    def test_hex_escape_blocks(self):
        result = validate_jql_input("get_jira_issues", "project = 0x50524F4A")
        assert result is not None

    def test_length_limit(self):
        result = validate_jql_input("get_jira_issues", "a" * 2001)
        assert result is not None
        assert "maximum length" in result["message"]


# ======================================================================
# Guardrail 5: SQL Read-Only Validation
# ======================================================================

class TestSqlReadOnly:
    def test_select_passes(self):
        assert validate_sql_readonly("teradata_read_query", "SELECT * FROM employees") is None

    def test_with_passes(self):
        assert validate_sql_readonly("teradata_read_query", "WITH cte AS (SELECT 1) SELECT * FROM cte") is None

    def test_insert_blocks(self):
        result = validate_sql_readonly("teradata_read_query", "INSERT INTO users VALUES (1, 'test')")
        assert result is not None
        assert result["guardrail"] == "sql_readonly"

    def test_drop_keyword_blocks(self):
        result = validate_sql_readonly("teradata_read_query", "SELECT 1; DROP TABLE users")
        assert result is not None  # Blocked by semicolon check

    def test_semicolon_blocks(self):
        result = validate_sql_readonly("teradata_read_query", "SELECT 1; SELECT 2")
        assert result is not None
        assert "semicolons" in result["message"]

    def test_non_teradata_skipped(self):
        """Non-Teradata tools skip SQL validation."""
        assert validate_sql_readonly("jira_get_issue_details", "DROP TABLE users") is None

    def test_length_limit(self):
        result = validate_sql_readonly("teradata_read_query", "SELECT " + "a" * 5001)
        assert result is not None

    def test_empty_passes(self):
        assert validate_sql_readonly("teradata_read_query", "") is None


# ======================================================================
# Guardrail 6: Project Scope Enforcement
# ======================================================================

class TestProjectScope:
    def test_wildcard_allows_all(self):
        assert check_project_scope("jira_get_issue_details", ["*"], issue_key="ANY-123") is None

    def test_authorized_project_passes(self):
        assert check_project_scope("jira_get_issue_details", ["PROJ"], issue_key="PROJ-123") is None

    def test_unauthorized_project_blocks(self):
        result = check_project_scope("jira_get_issue_details", ["PROJ"], issue_key="OTHER-456")
        assert result is not None
        assert result["guardrail"] == "project_scope"
        assert "OTHER" in result["message"]

    def test_jql_project_extraction(self):
        result = check_project_scope(
            "get_jira_issues", ["PROJ"],
            jql="project = UNAUTHORIZED AND status = Open",
        )
        assert result is not None

    def test_jql_authorized_project(self):
        result = check_project_scope(
            "get_jira_issues", ["MYPROJ"],
            jql="project = MYPROJ AND status = Open",
        )
        assert result is None


# ======================================================================
# Guardrail 7: Write Rate Limiting
# ======================================================================

class TestWriteRateLimit:
    def test_read_tool_skipped(self):
        assert check_write_rate_limit("consumer-1", "get_jira_issues") is None

    def test_write_within_limit(self):
        # Use a unique consumer to avoid cross-test pollution
        result = check_write_rate_limit("test-write-ok", "jira_create_issue")
        assert result is None


# ======================================================================
# Full Pipeline Orchestrator
# ======================================================================

class TestEnforceGuardrails:
    def test_all_pass(self):
        result = enforce_guardrails(
            tool_name="get_jira_issues",
            consumer_id="test-consumer",
            allowed_tools=["*"],
            projects=["*"],
        )
        assert result is None

    def test_unauthorized_tool_blocks(self):
        result = enforce_guardrails(
            tool_name="jira_create_issue",
            consumer_id="test-consumer",
            allowed_tools=["get_jira_issues"],
        )
        assert result is not None
        assert result["guardrail"] == "tool_authorization"

    def test_pipeline_short_circuits(self):
        """Pipeline stops at first failure (tool auth before write auth)."""
        result = enforce_guardrails(
            tool_name="jira_create_issue",
            consumer_id="test-consumer",
            allowed_tools=["neo4j_run_query"],
            consumer_type="ai-agent",
            user_groups=[],
        )
        assert result is not None
        assert result["guardrail"] == "tool_authorization"
