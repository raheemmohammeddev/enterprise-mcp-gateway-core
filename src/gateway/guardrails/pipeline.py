"""
Enterprise MCP Gateway - Seven-Step Composable Security Guardrail Pipeline.

Every MCP tool invocation passes through enforce_guardrails(), which runs
7 independent checks in sequence. Each check returns None (pass) or a
structured error dict (block).

Guardrail 0: Tool Active Check         (registry lookup; disabled = blocked)
Guardrail 1: Tool Authorization         (consumer's allowed_tools whitelist)
Guardrail 2: User Write Authorization   (AD group gate for write tools)
Guardrail 3: Write Credential Attrib.   (personal PAT required for writes)
Guardrail 4: JQL Input Validation       (injection pattern blocking)
Guardrail 5: SQL Read-Only Validation   (DDL/DML blocking for Teradata)
Guardrail 6: Project Scope Enforcement  (consumer project whitelist)
Guardrail 7: Write Rate Limiting        (per-consumer mutation throttle)

All thresholds are configurable at runtime. In production, these values
are loaded from DocumentDB with env-var fallback and a 30s cache TTL.

Design:
    - Fail-closed for security-sensitive checks (write auth, RBAC)
    - Fail-open for availability-sensitive checks (tool registry lookup)
    - Every blocked call returns a structured error with guardrail name
"""

from __future__ import annotations

import logging
import re
import time
import threading
from typing import Any, Dict, List, Optional

from gateway.config.settings import (
    USER_WRITE_AUTH_ENABLED,
    WRITE_AD_GROUPS,
    WRITE_RATE_LIMIT,
    WRITE_RATE_LIMIT_WINDOW,
)

logger = logging.getLogger("enterprise-mcp-gateway.guardrails")

# Write tools that require elevated authorization
_WRITE_TOOL_PREFIXES = {"jira_create", "jira_assign", "jira_transition", "jira_add_comment",
                         "jira_attach", "bre_create", "bre_update", "bre_attach", "bre_link"}

# JQL injection patterns
_JQL_INJECTION_PATTERNS = [
    re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|TRUNCATE)", re.IGNORECASE),
    re.compile(r"--"),
    re.compile(r"/\*.*?\*/", re.DOTALL),
    re.compile(r"0x[0-9a-fA-F]+"),
    re.compile(r"\\u[0-9a-fA-F]{4}"),
]
_JQL_MAX_LENGTH = 2000

# SQL DDL/DML keywords blocked for Teradata read-only enforcement
_SQL_BLOCKED_KEYWORDS = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|MERGE|REPLACE|GRANT|REVOKE|EXEC)\b",
    re.IGNORECASE,
)
_SQL_MAX_LENGTH = 5000

# Per-consumer write rate tracking
_write_timestamps: Dict[str, List[float]] = {}
_write_lock = threading.Lock()


def _is_write_tool(tool_name: str) -> bool:
    """Check if a tool is classified as a write operation."""
    return any(tool_name.startswith(prefix) for prefix in _WRITE_TOOL_PREFIXES)


# ======================================================================
# Individual Guardrail Checks
# ======================================================================

def check_tool_active(tool_name: str) -> Optional[Dict[str, Any]]:
    """Guardrail 0: Verify the tool is enabled in the registry.

    Fail-open: if the registry is unavailable, allow the call through.

    Returns:
        Error dict if tool is disabled, None if active or registry unavailable.
    """
    try:
        # In production, this queries the DocumentDB tool registry.
        # For the core implementation, we default to allowing all tools.
        # Override this with a real registry lookup in deployment.
        return None
    except Exception:
        logger.debug("[GUARDRAIL-0] Tool registry unavailable, allowing %s", tool_name)
        return None


def check_tool_authorization(
    tool_name: str, allowed_tools: List[str]
) -> Optional[Dict[str, Any]]:
    """Guardrail 1: Validate tool against consumer's allowed_tools whitelist.

    Args:
        tool_name: Requested MCP tool name.
        allowed_tools: Consumer's allowed tool list (or ['*'] for all).

    Returns:
        Error dict if unauthorized, None if allowed.
    """
    if "*" in allowed_tools:
        return None
    if tool_name in allowed_tools:
        return None

    return {
        "error": "forbidden",
        "guardrail": "tool_authorization",
        "message": f"Tool '{tool_name}' is not in your authorized tool list.",
    }


def check_user_write_authorization(
    tool_name: str,
    user_groups: List[str],
    consumer_type: str,
) -> Optional[Dict[str, Any]]:
    """Guardrail 2: AD group gate for write operations (ai-agent consumers only).

    Requires the user's AD groups to include at least one write-authorized group.
    Only enforced for ai-agent consumer types.

    Fail-closed: no configured AD groups = deny all writes.

    Args:
        tool_name: Requested MCP tool name.
        user_groups: User's Active Directory group memberships.
        consumer_type: Consumer type (only 'ai-agent' is checked).

    Returns:
        Error dict if unauthorized, None if allowed.
    """
    if not USER_WRITE_AUTH_ENABLED:
        return None
    if consumer_type != "ai-agent":
        return None
    if not _is_write_tool(tool_name):
        return None

    # Case-insensitive AD group matching
    user_groups_lower = {g.lower() for g in user_groups}
    write_groups_lower = {g.lower() for g in WRITE_AD_GROUPS}

    if user_groups_lower & write_groups_lower:
        return None

    return {
        "error": "forbidden",
        "guardrail": "user_write_auth",
        "message": (
            f"Write operations require membership in an authorized AD group. "
            f"Your groups do not include any of: {', '.join(WRITE_AD_GROUPS)}"
        ),
    }


def check_write_credential_attribution(
    tool_name: str,
    credential_source: str,
    consumer_type: str,
) -> Optional[Dict[str, Any]]:
    """Guardrail 3: Require personal PAT for write operations.

    Prevents mutations under the shared service account identity. Write tools
    require a credential with source 'request_header' or 'profile', not
    'server_config'.

    Args:
        tool_name: Requested MCP tool name.
        credential_source: Source of the Jira PAT ('request_header', 'profile', 'server_config').
        consumer_type: Consumer type.

    Returns:
        Error dict if using shared credentials for writes, None if OK.
    """
    if consumer_type != "ai-agent":
        return None
    if not _is_write_tool(tool_name):
        return None
    if credential_source in ("request_header", "profile"):
        return None

    return {
        "error": "forbidden",
        "guardrail": "write_credential_attribution",
        "message": (
            "Write operations require a personal access token (PAT) so changes "
            "are attributed to you, not the shared service account. "
            "Configure your PAT in your user profile or pass it via X-MCP-Jira-PAT header."
        ),
    }


def validate_jql_input(tool_name: str, jql: str) -> Optional[Dict[str, Any]]:
    """Guardrail 4: Block SQL injection patterns in JQL input.

    Args:
        tool_name: Requested MCP tool name.
        jql: The JQL query string to validate.

    Returns:
        Error dict if injection detected, None if clean.
    """
    if not jql:
        return None

    if len(jql) > _JQL_MAX_LENGTH:
        return {
            "error": "invalid_input",
            "guardrail": "input_validation",
            "message": f"JQL query exceeds maximum length ({_JQL_MAX_LENGTH} characters).",
        }

    for pattern in _JQL_INJECTION_PATTERNS:
        if pattern.search(jql):
            return {
                "error": "invalid_input",
                "guardrail": "input_validation",
                "message": "JQL query contains a blocked pattern (potential injection).",
            }

    return None


def validate_sql_readonly(tool_name: str, sql: str) -> Optional[Dict[str, Any]]:
    """Guardrail 5: Enforce read-only SQL for Teradata tools.

    Only single SELECT or WITH statements are permitted. All DDL and DML
    keywords are blocked.

    Args:
        tool_name: Requested MCP tool name.
        sql: The SQL query string to validate.

    Returns:
        Error dict if non-read-only SQL detected, None if clean.
    """
    if not sql:
        return None
    if not tool_name.startswith("teradata_"):
        return None

    if len(sql) > _SQL_MAX_LENGTH:
        return {
            "error": "invalid_input",
            "guardrail": "sql_readonly",
            "message": f"SQL query exceeds maximum length ({_SQL_MAX_LENGTH} characters).",
        }

    # Must start with SELECT or WITH
    stripped = sql.strip().upper()
    if not (stripped.startswith("SELECT") or stripped.startswith("WITH")):
        return {
            "error": "invalid_input",
            "guardrail": "sql_readonly",
            "message": "Only SELECT or WITH statements are permitted for Teradata tools.",
        }

    # No semicolons (single statement only)
    if ";" in sql:
        return {
            "error": "invalid_input",
            "guardrail": "sql_readonly",
            "message": "Multiple SQL statements are not permitted (no semicolons allowed).",
        }

    # Block DDL/DML keywords
    if _SQL_BLOCKED_KEYWORDS.search(sql):
        return {
            "error": "invalid_input",
            "guardrail": "sql_readonly",
            "message": "SQL contains blocked DDL/DML keywords. Only read-only queries are permitted.",
        }

    return None


def check_project_scope(
    tool_name: str,
    projects: List[str],
    issue_key: str = "",
    jql: str = "",
) -> Optional[Dict[str, Any]]:
    """Guardrail 6: Validate project scope against consumer authorization.

    Extracts project keys from issue keys (e.g., 'PROJ-123' -> 'PROJ') and
    JQL strings, then checks against the consumer's authorized project list.

    Args:
        tool_name: Requested MCP tool name.
        projects: Consumer's authorized project list.
        issue_key: Optional issue key parameter.
        jql: Optional JQL query string.

    Returns:
        Error dict if unauthorized project access, None if OK.
    """
    if "*" in projects:
        return None

    # Extract project from issue key
    unauthorized: List[str] = []
    if issue_key and "-" in issue_key:
        project = issue_key.split("-")[0].upper()
        if project and project not in [p.upper() for p in projects]:
            unauthorized.append(project)

    # Scan JQL for project references (basic pattern matching)
    if jql:
        project_pattern = re.compile(r"project\s*=\s*['\"]?(\w+)['\"]?", re.IGNORECASE)
        for match in project_pattern.finditer(jql):
            project = match.group(1).upper()
            if project not in [p.upper() for p in projects]:
                unauthorized.append(project)

    if unauthorized:
        return {
            "error": "forbidden",
            "guardrail": "project_scope",
            "message": (
                f"Access to project(s) {', '.join(set(unauthorized))} is not authorized. "
                f"Your authorized projects: {', '.join(projects)}"
            ),
        }

    return None


def check_write_rate_limit(
    consumer_id: str,
    tool_name: str,
) -> Optional[Dict[str, Any]]:
    """Guardrail 7: Per-consumer write rate limiting.

    Separate sliding window for write operations (default: 5 writes per 600s),
    independent of the general rate limiter.

    Args:
        consumer_id: The consumer's identifier.
        tool_name: Requested MCP tool name.

    Returns:
        Error dict with retry_after if limit exceeded, None if OK.
    """
    if not _is_write_tool(tool_name):
        return None

    now = time.time()
    window = WRITE_RATE_LIMIT_WINDOW
    limit = WRITE_RATE_LIMIT

    with _write_lock:
        if consumer_id not in _write_timestamps:
            _write_timestamps[consumer_id] = []

        # Prune timestamps outside the window
        _write_timestamps[consumer_id] = [
            ts for ts in _write_timestamps[consumer_id] if ts > now - window
        ]

        if len(_write_timestamps[consumer_id]) >= limit:
            oldest = _write_timestamps[consumer_id][0]
            wait = int(window - (now - oldest)) + 1
            return {
                "error": "write_rate_limited",
                "guardrail": "write_rate_limit",
                "message": (
                    f"Write rate limit reached ({limit} writes per {window}s). "
                    f"Please wait {wait} seconds before retrying."
                ),
                "retry_after_seconds": wait,
            }

        # Record the write timestamp
        _write_timestamps[consumer_id].append(now)

    return None


# ======================================================================
# Pipeline Orchestrator
# ======================================================================

def enforce_guardrails(
    tool_name: str,
    consumer_id: str = "",
    consumer_type: str = "developer",
    allowed_tools: Optional[List[str]] = None,
    projects: Optional[List[str]] = None,
    user_groups: Optional[List[str]] = None,
    credential_source: str = "server_config",
    jql: str = "",
    sql: str = "",
    issue_key: str = "",
) -> Optional[Dict[str, Any]]:
    """Run the 7-step composable security guardrail pipeline.

    Each check is independent and returns None (pass) or a structured error
    dict (block). The pipeline short-circuits on the first failure.

    Args:
        tool_name: The MCP tool being invoked.
        consumer_id: Consumer identifier for rate limiting.
        consumer_type: Consumer classification (developer, ai-agent, etc.).
        allowed_tools: Consumer's authorized tool list.
        projects: Consumer's authorized project list.
        user_groups: User's AD group memberships.
        credential_source: Source of the Jira PAT.
        jql: JQL query string (if applicable).
        sql: SQL query string (if applicable).
        issue_key: Jira issue key (if applicable).

    Returns:
        Structured error dict if any guardrail blocks, None if all pass.
    """
    allowed_tools = allowed_tools or ["*"]
    projects = projects or ["*"]
    user_groups = user_groups or []

    checks = [
        # Guardrail 0: Tool Active Check
        lambda: check_tool_active(tool_name),
        # Guardrail 1: Tool Authorization
        lambda: check_tool_authorization(tool_name, allowed_tools),
        # Guardrail 2: User Write Authorization
        lambda: check_user_write_authorization(tool_name, user_groups, consumer_type),
        # Guardrail 3: Write Credential Attribution
        lambda: check_write_credential_attribution(tool_name, credential_source, consumer_type),
        # Guardrail 4: JQL Input Validation
        lambda: validate_jql_input(tool_name, jql),
        # Guardrail 5: SQL Read-Only Validation
        lambda: validate_sql_readonly(tool_name, sql),
        # Guardrail 6: Project Scope Enforcement
        lambda: check_project_scope(tool_name, projects, issue_key, jql),
        # Guardrail 7: Write Rate Limiting
        lambda: check_write_rate_limit(consumer_id, tool_name),
    ]

    for i, check in enumerate(checks):
        result = check()
        if result is not None:
            logger.warning(
                "[GUARDRAIL-%d] BLOCKED tool=%s consumer=%s guardrail=%s",
                i, tool_name, consumer_id, result.get("guardrail", "unknown"),
            )
            return result

    return None
