"""
Enterprise MCP Gateway - Neo4j Knowledge Graph Backend.

Provides read-only MCP tools for Neo4j graph database queries:
    - Schema introspection (labels, relationships, properties)
    - Cypher query validation (regex-based, read-only enforcement)
    - Cypher query execution with auto-LIMIT injection

Also provides the only MCP resource and the only MCP prompt the gateway
advertises:
    - Resource graph://neo4j/schema: the schema above plus connected
      (:Label)-[:REL]->(:Label) relationship patterns, which the flat tool
      output does not carry.
    - Prompt cypher_query_guidance: Cypher composition help that embeds those
      patterns and the gateway's real read-only constraints.

Both run the same guardrail pipeline as the tools, so a caller denied a tool
cannot read the equivalent data through the resource or the prompt.

Multi-instance support: production and experimentation instances are
selectable per query.

Self-disables when NEO4J_ENABLED=false.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

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

# Hard cap applied to the auto-injected LIMIT clause, mirrored in the prompt.
_MAX_LIMIT = 500

# Neo4j 5.x built-in that returns the connected shape of the graph. CALL db.*
# is permitted by the read-only validator above; CALL dbms is not.
_SCHEMA_VISUALIZATION = "CALL db.schema.visualization()"

# URI and name under which the schema resource and the Cypher prompt are
# advertised. Kept as constants so the registration and the tests agree.
SCHEMA_RESOURCE_URI = "graph://neo4j/schema"
CYPHER_PROMPT_NAME = "cypher_query_guidance"


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


def _check_read_only(query: str) -> Dict[str, Any]:
    """Regex-based read-only validation shared by the Neo4j tools.

    Kept separate from the neo4j_validate_query tool so neo4j_run_query can
    reuse the check without re-entering that tool's own guardrail pipeline
    (which would authorize against the wrong tool name).

    Args:
        query: The Cypher query string to validate.

    Returns:
        Dict with 'valid' and 'message' keys.
    """
    if _WRITE_KEYWORDS.search(query):
        return {
            "valid": False,
            "message": "Query contains write operations (CREATE, MERGE, DELETE, etc.).",
        }
    return {"valid": True, "message": "Query passes read-only validation."}


@audit_log
@rate_limited
def neo4j_get_schema(instance: Optional[str] = None) -> Dict[str, Any]:
    """Get the graph schema (labels, relationships, property keys).

    Args:
        instance: Optional instance identifier (for multi-instance setups).

    Returns:
        Dict with node labels, relationship types, and property keys.
    """
    from gateway.guardrails.pipeline import caller_guardrail_scope, enforce_guardrails

    block = enforce_guardrails(
        tool_name="neo4j_get_schema",
        **caller_guardrail_scope(),
    )
    if block:
        return block

    # Authorization decides first: backend enablement state is only disclosed
    # to a caller the guardrails already allowed.
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
    from gateway.guardrails.pipeline import caller_guardrail_scope, enforce_guardrails

    block = enforce_guardrails(
        tool_name="neo4j_validate_query",
        **caller_guardrail_scope(),
    )
    if block:
        return block

    return _check_read_only(query)


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
    from gateway.guardrails.pipeline import caller_guardrail_scope, enforce_guardrails

    block = enforce_guardrails(
        tool_name="neo4j_run_query",
        **caller_guardrail_scope(),
    )
    if block:
        return block

    # Authorization decides first: backend enablement state is only disclosed
    # to a caller the guardrails already allowed.
    if not NEO4J_ENABLED:
        return {"error": "neo4j_disabled", "message": "Neo4j is disabled in this environment."}

    # Read-only enforcement
    validation = _check_read_only(query)
    if not validation.get("valid", False):
        return {"error": "neo4j_write_blocked", "message": validation.get("message", "")}

    # Auto-limit injection
    query = _apply_limit(query, cap=min(limit, _MAX_LIMIT))

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


# ======================================================================
# MCP Resource: Graph Schema
# ======================================================================

def _node_label(node: Any) -> str:
    """Best-effort label of a virtual node from db.schema.visualization().

    The procedure returns virtual nodes whose label is carried both in
    Node.labels and in a 'name' property, so both are tried.

    Args:
        node: Node object (or stub) from the procedure result.

    Returns:
        A single label string, empty if none could be read.
    """
    labels = getattr(node, "labels", None)
    if labels:
        return sorted(str(label) for label in labels)[0]
    try:
        name = node.get("name")
    except Exception:
        name = None
    return str(name) if name else ""


def _extract_relationship_patterns(records: Iterable[Any]) -> List[Dict[str, str]]:
    """Build connected (start)-[type]->(end) patterns from a result set.

    Args:
        records: Rows from db.schema.visualization(), each exposing a
            'relationships' column.

    Returns:
        De-duplicated pattern dicts in first-seen order.
    """
    patterns: List[Dict[str, str]] = []
    seen = set()

    for record in records:
        for rel in record.get("relationships") or []:
            rel_type = str(getattr(rel, "type", "") or "")
            if not rel_type:
                continue
            key = (
                _node_label(getattr(rel, "start_node", None)),
                rel_type,
                _node_label(getattr(rel, "end_node", None)),
            )
            if key in seen:
                continue
            seen.add(key)
            patterns.append({"start": key[0], "type": key[1], "end": key[2]})

    return patterns


def _read_relationship_patterns(session: Any) -> Tuple[List[Dict[str, str]], str]:
    """Read relationship patterns, degrading honestly when unavailable.

    Args:
        session: An open Neo4j session.

    Returns:
        (patterns, notes). notes is empty on success and explains the empty
        pattern list otherwise. Patterns are never fabricated.
    """
    try:
        records = list(session.run(_SCHEMA_VISUALIZATION))
    except Exception as exc:
        logger.warning("[NEO4J] %s unavailable: %s", _SCHEMA_VISUALIZATION, exc)
        return [], (
            "Relationship patterns are unavailable: %s failed on this server "
            "(%s)." % (_SCHEMA_VISUALIZATION, exc)
        )

    patterns = _extract_relationship_patterns(records)
    if not patterns:
        return [], (
            "Relationship patterns are empty: %s reported no connected "
            "patterns." % _SCHEMA_VISUALIZATION
        )
    return patterns, ""


def neo4j_schema_resource() -> Dict[str, Any]:
    """Graph schema resource: labels, relationships, properties and patterns.

    Serves the same data as the neo4j_get_schema tool plus the connected
    relationship patterns the flat tool output omits, which is what lets a
    model avoid inventing relationship types.

    Authorization: identical to neo4j_get_schema, enforced before any driver
    work, so a caller denied that tool is denied this resource.

    Returns:
        Dict with labels, relationship_types, property_keys,
        relationship_patterns and notes; or the guardrail block dict, or one
        of the standard neo4j_disabled / neo4j_unavailable / neo4j_error
        dicts, unchanged.
    """
    from gateway.guardrails.pipeline import caller_guardrail_scope, enforce_guardrails

    block = enforce_guardrails(
        tool_name="neo4j_get_schema",
        **caller_guardrail_scope(),
    )
    if block:
        return block

    # Authorization decides first: backend enablement state is only disclosed
    # to a caller the guardrails already allowed.
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
            patterns, notes = _read_relationship_patterns(session)

        return {
            "labels": labels,
            "relationship_types": rel_types,
            "property_keys": props,
            "relationship_patterns": patterns,
            "notes": notes,
        }
    except Exception as exc:
        return {"error": "neo4j_error", "message": str(exc)}
    finally:
        if driver:
            driver.close()


# ======================================================================
# MCP Prompt: Cypher Composition Guidance
# ======================================================================

def _format_schema_section(schema: Dict[str, Any]) -> str:
    """Render the resource payload as the schema section of the prompt.

    Args:
        schema: The payload returned by neo4j_schema_resource().

    Returns:
        Prompt text describing the live schema, or why it is absent. Never
        invents labels or relationship patterns.
    """
    if schema.get("error"):
        return (
            "Live schema unavailable (%s). Do not guess labels or "
            "relationship types; ask the caller to confirm them."
            % schema["error"]
        )

    lines = ["Live schema of the connected graph:"]
    labels = schema.get("labels") or []
    lines.append("- Node labels: %s" % (", ".join(labels) if labels else "none reported"))

    patterns = schema.get("relationship_patterns") or []
    if patterns:
        lines.append("- Relationship patterns:")
        for pattern in patterns:
            lines.append(
                "  (:%s)-[:%s]->(:%s)"
                % (pattern.get("start", ""), pattern.get("type", ""), pattern.get("end", ""))
            )
    else:
        lines.append(
            "- Relationship patterns: none available, so do not assume any "
            "relationship type or direction."
        )

    notes = schema.get("notes")
    if notes:
        lines.append("- Note: %s" % notes)

    return "\n".join(lines)


def cypher_query_guidance(question: str) -> Any:
    """Guidance for composing a read-only Cypher query for this graph.

    Embeds the live schema (labels plus connected relationship patterns) and
    the constraints the gateway actually enforces, so the model composes a
    query that passes validation instead of one that has to be retried.

    Authorization: the prompt itself is query-composition help, so it
    authorizes against neo4j_validate_query as the least-privilege match. The
    live schema it embeds is neo4j_get_schema data, so that data is only
    included when the caller is also authorized for neo4j_get_schema;
    otherwise the guidance is returned without it.

    Args:
        question: The question the Cypher query must answer.

    Returns:
        The prompt string, or the guardrail block dict unchanged.
    """
    from gateway.guardrails.pipeline import caller_guardrail_scope, enforce_guardrails

    block = enforce_guardrails(
        tool_name="neo4j_validate_query",
        **caller_guardrail_scope(),
    )
    if block:
        return block

    schema_block = enforce_guardrails(
        tool_name="neo4j_get_schema",
        **caller_guardrail_scope(),
    )
    if schema_block:
        schema_section = (
            "Live schema withheld: this caller is not authorized for "
            "neo4j_get_schema. Do not guess labels or relationship types; "
            "ask the caller to supply them."
        )
    else:
        schema_section = _format_schema_section(neo4j_schema_resource())

    return (
        "Compose a read-only Cypher query for the knowledge graph this MCP "
        "gateway exposes.\n\n"
        "Question to answer:\n"
        "%s\n\n"
        "%s\n\n"
        "Constraints the gateway enforces on every query:\n"
        "- Read-only: CREATE, MERGE, SET, DELETE, DETACH, REMOVE, DROP and "
        "CALL dbms are blocked and the call is rejected before it reaches "
        "the database.\n"
        "- A LIMIT clause is injected automatically when the query lacks "
        "one, and the effective cap is at most %d rows.\n"
        "- Use only the relationship types and directions listed above; do "
        "not invent relationships.\n"
        "- Match on explicit labels and return named columns.\n\n"
        "Return the Cypher query only." % (question, schema_section, _MAX_LIMIT)
    )


def register(mcp: Any) -> None:
    """Register all Neo4j MCP tools, the schema resource and the Cypher prompt.

    Nothing is registered when the backend is disabled, so the advertised
    capability set never claims more than the gateway can serve.

    Args:
        mcp: FastMCP server instance.
    """
    if not NEO4J_ENABLED:
        logger.info("[NEO4J] Neo4j is disabled -- skipping tool registration")
        return

    mcp.tool()(neo4j_get_schema)
    mcp.tool()(neo4j_validate_query)
    mcp.tool()(neo4j_run_query)
    mcp.resource(SCHEMA_RESOURCE_URI, mime_type="application/json")(neo4j_schema_resource)
    mcp.prompt(name=CYPHER_PROMPT_NAME)(cypher_query_guidance)
    logger.info(
        "[NEO4J] Registered 3 Neo4j Knowledge Graph tools (read-only), "
        "1 resource (%s) and 1 prompt (%s)",
        SCHEMA_RESOURCE_URI, CYPHER_PROMPT_NAME,
    )
