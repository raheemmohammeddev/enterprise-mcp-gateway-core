"""
Enterprise MCP Gateway - Jira Backend (Project Management).

Provides MCP tools for Jira read/write operations with multi-backend dispatch:
    - PAT (direct REST with Bearer token)
    - Basic (email + API token)
    - Enterprise LLM Orchestrator (JSON-RPC routing)

Backend selection is dynamic and configurable per environment via DocumentDB
or the JIRA_BACKEND environment variable.

All tools are wrapped with the standard decorator composition order:
    @jira_audited -> @rate_limited -> tool logic
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from gateway.audit.loggers import jira_audited
from gateway.config.settings import JIRA_BASE_URL, JIRA_BACKEND, JIRA_PAT
from gateway.ratelimit.limiter import rate_limited

logger = logging.getLogger("enterprise-mcp-gateway.jira")

# Timeout for Jira REST API calls
_JIRA_TIMEOUT = 30


def _get_auth_headers() -> Dict[str, str]:
    """Build authentication headers based on configured backend mode.

    Returns:
        Dict of HTTP headers for Jira REST API calls.
    """
    if JIRA_BACKEND == "pat" and JIRA_PAT:
        return {"Authorization": f"Bearer {JIRA_PAT}", "Content-Type": "application/json"}
    return {"Content-Type": "application/json"}


def _jira_get(endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute a GET request against the Jira REST API.

    Args:
        endpoint: API path (e.g., '/rest/api/2/search').
        params: Query parameters.

    Returns:
        Parsed JSON response, or error dict on failure.
    """
    url = f"{JIRA_BASE_URL}{endpoint}"
    try:
        with httpx.Client(timeout=_JIRA_TIMEOUT) as client:
            resp = client.get(url, headers=_get_auth_headers(), params=params)
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        return {"error": "jira_timeout", "message": f"Jira request timed out after {_JIRA_TIMEOUT}s"}
    except httpx.HTTPStatusError as exc:
        return {"error": "jira_http_error", "message": f"Jira returned HTTP {exc.response.status_code}"}
    except Exception as exc:
        return {"error": "jira_error", "message": str(exc)}


def _jira_post(endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Execute a POST request against the Jira REST API.

    Args:
        endpoint: API path.
        payload: JSON request body.

    Returns:
        Parsed JSON response, or error dict on failure.
    """
    url = f"{JIRA_BASE_URL}{endpoint}"
    try:
        with httpx.Client(timeout=_JIRA_TIMEOUT) as client:
            resp = client.post(url, headers=_get_auth_headers(), json=payload)
            resp.raise_for_status()
            return resp.json() if resp.content else {"success": True}
    except httpx.TimeoutException:
        return {"error": "jira_timeout", "message": f"Jira request timed out after {_JIRA_TIMEOUT}s"}
    except httpx.HTTPStatusError as exc:
        return {"error": "jira_http_error", "message": f"Jira returned HTTP {exc.response.status_code}"}
    except Exception as exc:
        return {"error": "jira_error", "message": str(exc)}


# ======================================================================
# MCP Tool Handlers
# ======================================================================

@jira_audited
@rate_limited
def get_jira_issues(jql: str, max_results: int = 20) -> Dict[str, Any]:
    """Search Jira issues by JQL query.

    Args:
        jql: Jira Query Language string.
        max_results: Maximum results to return (capped at 50).

    Returns:
        Dict with issue list and metadata.
    """
    from gateway.guardrails.pipeline import enforce_guardrails
    from gateway.middleware.auth import get_current_caller

    caller = get_current_caller()
    block = enforce_guardrails(
        tool_name="get_jira_issues",
        consumer_id=caller.consumer.consumer if caller and caller.consumer else "",
        consumer_type=caller.consumer.type if caller and caller.consumer else "developer",
        allowed_tools=caller.consumer.allowed_tools if caller and caller.consumer else ["*"],
        projects=caller.consumer.projects if caller and caller.consumer else ["*"],
        user_groups=caller.user_groups if caller else [],
        jql=jql,
    )
    if block:
        return block

    max_results = min(max_results, 50)
    return _jira_get("/rest/api/2/search", params={"jql": jql, "maxResults": max_results})


@jira_audited
@rate_limited
def jira_get_issue_details(issue_key: str) -> Dict[str, Any]:
    """Get full details for a Jira issue by key.

    Args:
        issue_key: The issue key (e.g., 'PROJ-123').

    Returns:
        Dict with issue fields, status, and metadata.
    """
    from gateway.guardrails.pipeline import enforce_guardrails
    from gateway.middleware.auth import get_current_caller

    caller = get_current_caller()
    block = enforce_guardrails(
        tool_name="jira_get_issue_details",
        consumer_id=caller.consumer.consumer if caller and caller.consumer else "",
        allowed_tools=caller.consumer.allowed_tools if caller and caller.consumer else ["*"],
        projects=caller.consumer.projects if caller and caller.consumer else ["*"],
        issue_key=issue_key,
    )
    if block:
        return block

    return _jira_get(f"/rest/api/2/issue/{issue_key}")


@jira_audited
@rate_limited
def jira_create_issue(
    project: str, summary: str, issue_type: str = "Task",
    description: str = "", assignee: str = "",
) -> Dict[str, Any]:
    """Create a new Jira issue.

    Args:
        project: Project key (e.g., 'PROJ').
        summary: Issue summary/title.
        issue_type: Issue type (Task, Bug, Story, etc.).
        description: Issue description body.
        assignee: Assignee username (optional).

    Returns:
        Dict with created issue key and URL.
    """
    from gateway.guardrails.pipeline import enforce_guardrails
    from gateway.middleware.auth import get_current_caller, get_current_jira_pat_source

    caller = get_current_caller()
    block = enforce_guardrails(
        tool_name="jira_create_issue",
        consumer_id=caller.consumer.consumer if caller and caller.consumer else "",
        consumer_type=caller.consumer.type if caller and caller.consumer else "developer",
        allowed_tools=caller.consumer.allowed_tools if caller and caller.consumer else ["*"],
        projects=caller.consumer.projects if caller and caller.consumer else ["*"],
        user_groups=caller.user_groups if caller else [],
        credential_source=get_current_jira_pat_source(),
        issue_key=f"{project}-0",
    )
    if block:
        return block

    fields: Dict[str, Any] = {
        "project": {"key": project},
        "summary": summary,
        "issuetype": {"name": issue_type},
    }
    if description:
        fields["description"] = description
    if assignee:
        fields["assignee"] = {"name": assignee}

    return _jira_post("/rest/api/2/issue", {"fields": fields})


@jira_audited
@rate_limited
def jira_add_comment(issue_key: str, comment: str) -> Dict[str, Any]:
    """Add a comment to a Jira issue.

    Args:
        issue_key: The issue key (e.g., 'PROJ-123').
        comment: Comment text body.

    Returns:
        Dict with comment ID and status.
    """
    from gateway.guardrails.pipeline import enforce_guardrails
    from gateway.middleware.auth import get_current_caller, get_current_jira_pat_source

    caller = get_current_caller()
    block = enforce_guardrails(
        tool_name="jira_add_comment",
        consumer_id=caller.consumer.consumer if caller and caller.consumer else "",
        consumer_type=caller.consumer.type if caller and caller.consumer else "developer",
        allowed_tools=caller.consumer.allowed_tools if caller and caller.consumer else ["*"],
        user_groups=caller.user_groups if caller else [],
        credential_source=get_current_jira_pat_source(),
        issue_key=issue_key,
    )
    if block:
        return block

    return _jira_post(f"/rest/api/2/issue/{issue_key}/comment", {"body": comment})


# ======================================================================
# Tool Registration
# ======================================================================

def register(mcp: Any) -> None:
    """Register all Jira MCP tools with the FastMCP server.

    Args:
        mcp: FastMCP server instance.
    """
    mcp.tool()(get_jira_issues)
    mcp.tool()(jira_get_issue_details)
    mcp.tool()(jira_create_issue)
    mcp.tool()(jira_add_comment)
    logger.info("[JIRA] Registered 4 Jira tools (read + write)")
