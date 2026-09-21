"""
Enterprise MCP Gateway - Neo4j Knowledge Graph Backend.

Provides read-only MCP tools for Neo4j graph database queries:
    - Schema introspection (labels, relationships, properties)
    - Cypher query validation (regex-based, read-only enforcement)
    - Cypher query execution with auto-LIMIT injection

Multi-instance support: production and experimentation instances are
selectable per query.

Self-disables when NEO4J_ENABLED=false.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional

from gateway.audit.loggers import audit_log
from gateway.config.settings import (
    NEO4J_ENABLED,
    NEO4J_PASSWORD,
    NEO4J_TIMEOUT_SECONDS,
    NEO4J_URI,
    NEO4J_USERNAME,
)
from gateway.ratelimit.limiter import rate_limited

logger = logging.getLogger("enterprise-mcp-gateway.neo4j")

# Cypher write keywords blocked by the read-only validator
_WRITE_KEYWORDS = re.compile(
    r"\b(CREATE|MERGE|SET|DELETE|DETACH|REMOVE|DROP|CALL\s+dbms)\b",
    re.IGNORECASE,
)

_DEFAULT_LIMIT = 50


def _get_driver():
    """Get or create a Neo4j driver instance.

    Returns:
        Neo4j driver, or None if unavailable.
    """
    if not NEO4J_ENABLED:
        return None
    try:
        from neo4j import GraphDatabase
        return GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USERNAME, NEO4J_PASSWORD),
            connection_timeout=NEO4J_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        logger.warning("[NEO4J] Driver initialization failed: %s", exc)
        return None


def _apply_limit(query: str, cap: int = _DEFAULT_LIMIT) -> str:
    """Inject a LIMIT clause if the query lacks one.

    Prevents unbounded result sets from exhausting memory.

    Args:
        query: The Cypher query string.
        cap: Maximum rows to return.

    Returns:
        Query with LIMIT clause appended if missing.
    """
    if re.search(r"\bLIMIT\b", query, re.IGNORECASE):
        return query
    return f"{query.rstrip().rstrip(';')} LIMIT {cap}"


@audit_log
@rate_limited
def neo4j_get_schema(instance: Optional[str] = None) -> Dict[str, Any]:
    """Get the graph schema (labels, relationships, property keys).

    Args:
        instance: Optional instance identifier (for multi-instance setups).

    Returns:
        Dict with node labels, relationship types, and property keys.
    """
    if not NEO4J_ENABLED:
        return {"error": "neo4j_disabled", "message": "Neo4j is disabled in this environment."}

    driver = _get_driver()
    if driver is None:
        return {"error": "neo4j_unavailable", "message": "Neo4j driver is not available."}

    try:
        with driver.session() as session:
            labels = [r["label"] for r in session.run("CALL db.labels()")]
            rel_types = [r["relationshipType"] for r in session.run("CALL db.relationshipTypes()")]
            props = [r["propertyKey"] for r in session.run("CALL db.propertyKeys()")]

        return {
            "labels": labels,
            "relationship_types": rel_types,
            "property_keys": props,
        }
    except Exception as exc:
        return {"error": "neo4j_error", "message": str(exc)}
    finally:
        if driver:
            driver.close()


@audit_log
@rate_limited
def neo4j_validate_query(query: str) -> Dict[str, Any]:
    """Validate a Cypher query for read-only safety (no DB access needed).

    Uses regex-based detection of write keywords. Does not execute the query.

    Args:
        query: The Cypher query string to validate.

    Returns:
        Dict with validation result.
    """
    if _WRITE_KEYWORDS.search(query):
        return {
            "valid": False,
            "message": "Query contains write operations (CREATE, MERGE, DELETE, etc.).",
        }
    return {"valid": True, "message": "Query passes read-only validation."}


@audit_log
@rate_limited
def neo4j_run_query(query: str, limit: int = _DEFAULT_LIMIT) -> Dict[str, Any]:
    """Execute a read-only Cypher query against the Neo4j knowledge graph.

    Enforces read-only at the gateway level (write keyword blocking) and
    injects a LIMIT clause if missing.

    Args:
        query: The Cypher query string.
        limit: Maximum rows to return (default 50).

    Returns:
        Dict with query results as a list of record dicts.
    """
    if not NEO4J_ENABLED:
        return {"error": "neo4j_disabled", "message": "Neo4j is disabled in this environment."}

    # Read-only enforcement
    validation = neo4j_validate_query.__wrapped__(query)  # type: ignore[attr-defined]
    if not validation.get("valid", False):
        return {"error": "neo4j_write_blocked", "message": validation.get("message", "")}

    # Auto-limit injection
    query = _apply_limit(query, cap=min(limit, 500))

    driver = _get_driver()
    if driver is None:
        return {"error": "neo4j_unavailable", "message": "Neo4j driver is not available."}

    try:
        with driver.session() as session:
            result = session.run(query)
            records = [dict(record) for record in result]

        return {"results": records, "count": len(records)}
    except Exception as exc:
        return {"error": "neo4j_error", "message": str(exc)}
    finally:
        if driver:
            driver.close()


def register(mcp: Any) -> None:
    """Register all Neo4j MCP tools with the FastMCP server.

    Args:
        mcp: FastMCP server instance.
    """
    if not NEO4J_ENABLED:
        logger.info("[NEO4J] Neo4j is disabled -- skipping tool registration")
        return

    mcp.tool()(neo4j_get_schema)
    mcp.tool()(neo4j_validate_query)
    mcp.tool()(neo4j_run_query)
    logger.info("[NEO4J] Registered 3 Neo4j Knowledge Graph tools (read-only)")
