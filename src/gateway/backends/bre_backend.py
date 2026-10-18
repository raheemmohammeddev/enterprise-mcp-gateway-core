"""
Enterprise MCP Gateway - Business Rule Engine / Reference Data Service Backend.

Registers 4 MCP tools for BRE/RDS workflow operations: access checks,
document retrieval, picklist loading, and search.

NOT YET IMPLEMENTED: all 4 tools are stubs. They run the security guardrail
pipeline and then return a canned "requires API configuration" response -
no BRE/RDS backend call is made.

All tools use the standard decorator composition:
    @audit_log -> @rate_limited -> tool logic

Terminology (vendor-neutral):
    BRE = Business Rule Engine (manages structured business documents)
    RDS = Reference Data Service (provides picklist/lookup data)
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from gateway.audit.loggers import audit_log
from gateway.ratelimit.limiter import rate_limited

logger = logging.getLogger("enterprise-mcp-gateway.bre")


@audit_log
@rate_limited
def bre_check_access(user_pid: str) -> Dict[str, Any]:
    """Stub - not yet implemented. Pre-check a user's BRE authorization.

    Returns a canned not-configured response; no BRE/RDS API call is made.

    Args:
        user_pid: User's personnel identifier.

    Returns:
        Dict describing the user's BRE access level and permissions.
    """
    from gateway.guardrails.pipeline import enforce_guardrails
    from gateway.middleware.auth import get_current_caller

    caller = get_current_caller()
    block = enforce_guardrails(
        tool_name="bre_check_access",
        consumer_id=caller.consumer.consumer if caller and caller.consumer else "",
        consumer_type=caller.consumer.type if caller and caller.consumer else "developer",
        allowed_tools=caller.consumer.allowed_tools if caller and caller.consumer else ["*"],
        projects=caller.consumer.projects if caller and caller.consumer else ["*"],
        user_groups=caller.user_groups if caller else [],
    )
    if block:
        return block

    # In production, this queries the BRE role API
    return {
        "user_pid": user_pid,
        "can_create": False,
        "can_edit": False,
        "roles": [],
        "message": "BRE access check requires RDS API configuration.",
    }


@audit_log
@rate_limited
def bre_get_details(document_id: str) -> Dict[str, Any]:
    """Stub - not yet implemented. Get full details for a BRE document.

    Returns a canned not-configured response; no BRE/RDS API call is made.

    Args:
        document_id: The document identifier.

    Returns:
        Dict with document fields, status, and metadata.
    """
    from gateway.guardrails.pipeline import enforce_guardrails
    from gateway.middleware.auth import get_current_caller

    caller = get_current_caller()
    block = enforce_guardrails(
        tool_name="bre_get_details",
        consumer_id=caller.consumer.consumer if caller and caller.consumer else "",
        consumer_type=caller.consumer.type if caller and caller.consumer else "developer",
        allowed_tools=caller.consumer.allowed_tools if caller and caller.consumer else ["*"],
        projects=caller.consumer.projects if caller and caller.consumer else ["*"],
        user_groups=caller.user_groups if caller else [],
    )
    if block:
        return block

    return {
        "document_id": document_id,
        "error": "bre_not_configured",
        "message": "BRE/RDS backend requires API configuration.",
    }


@audit_log
@rate_limited
def bre_get_picklists(list_name: str) -> Dict[str, Any]:
    """Stub - not yet implemented. Get Reference Data Service picklists.

    Returns a canned not-configured response; no BRE/RDS API call is made.

    Args:
        list_name: The picklist name to retrieve.

    Returns:
        Dict with picklist values.
    """
    from gateway.guardrails.pipeline import enforce_guardrails
    from gateway.middleware.auth import get_current_caller

    caller = get_current_caller()
    block = enforce_guardrails(
        tool_name="bre_get_picklists",
        consumer_id=caller.consumer.consumer if caller and caller.consumer else "",
        consumer_type=caller.consumer.type if caller and caller.consumer else "developer",
        allowed_tools=caller.consumer.allowed_tools if caller and caller.consumer else ["*"],
        projects=caller.consumer.projects if caller and caller.consumer else ["*"],
        user_groups=caller.user_groups if caller else [],
    )
    if block:
        return block

    return {
        "list_name": list_name,
        "values": [],
        "message": "BRE picklist cache requires RDS API configuration.",
    }


@audit_log
@rate_limited
def bre_search(query: str, max_results: int = 20) -> Dict[str, Any]:
    """Stub - not yet implemented. Search BRE documents by criteria.

    Returns a canned not-configured response; no BRE/RDS API call is made.

    Args:
        query: Search query string.
        max_results: Maximum results to return.

    Returns:
        Dict with matching documents.
    """
    from gateway.guardrails.pipeline import enforce_guardrails
    from gateway.middleware.auth import get_current_caller

    caller = get_current_caller()
    block = enforce_guardrails(
        tool_name="bre_search",
        consumer_id=caller.consumer.consumer if caller and caller.consumer else "",
        consumer_type=caller.consumer.type if caller and caller.consumer else "developer",
        allowed_tools=caller.consumer.allowed_tools if caller and caller.consumer else ["*"],
        projects=caller.consumer.projects if caller and caller.consumer else ["*"],
        user_groups=caller.user_groups if caller else [],
    )
    if block:
        return block

    return {
        "query": query,
        "results": [],
        "total": 0,
        "message": "BRE search requires backend configuration.",
    }


def register(mcp: Any) -> None:
    """Register all BRE/RDS MCP tools with the FastMCP server.

    Args:
        mcp: FastMCP server instance.
    """
    mcp.tool()(bre_check_access)
    mcp.tool()(bre_get_details)
    mcp.tool()(bre_get_picklists)
    mcp.tool()(bre_search)
    logger.info("[BRE] Registered 4 Business Rule Engine tools (stubs -- not implemented)")
