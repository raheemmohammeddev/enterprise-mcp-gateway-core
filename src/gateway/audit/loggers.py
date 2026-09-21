"""
Enterprise MCP Gateway - Multi-Pipeline Audit Logging.

Three parallel audit pipelines optimized per domain:

    Pipeline 1: Domain-Specific (Jira) - MCPJiraAudit collection
    Pipeline 2: Generic (BRE, Neo4j, Teradata) - MCPAuditLog collection
    Pipeline 3: Access Audit (Token generation) - MCPKiroAudit collection

Cross-cutting features:
    - SHA-256 credential fingerprinting for non-reversible correlation
    - Recursive log sanitization (credential redaction)
    - Fail-open design: audit failure does not block tool execution
    - Structured logging for Splunk/CloudWatch/Datadog forwarding

Design:
    Audit decorators (@jira_audited, @audit_log) wrap tool functions as the
    outermost decorator, capturing the entire request lifecycle including
    rate-limited and guardrail-blocked calls.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

from gateway.config.settings import (
    DOCDB_DATABASE,
    GENERIC_AUDIT_COLLECTION,
    JIRA_AUDIT_COLLECTION,
    KIRO_AUDIT_COLLECTION,
)

logger = logging.getLogger("enterprise-mcp-gateway.audit")

# Fail-open flag: once DocumentDB audit fails, disable for process lifetime
_audit_disabled = False

# Sensitive field patterns for recursive redaction
_SENSITIVE_FIELDS: Set[str] = {
    "authorization", "api_key", "apikey", "token", "pat", "password",
    "secret", "cookie", "credential", "session", "private_key",
}

_MAX_STRING_LENGTH = 500
_MAX_COLLECTION_SIZE = 50


# ======================================================================
# Credential Fingerprinting
# ======================================================================

def secret_fingerprint(secret: str) -> str:
    """Compute a non-reversible SHA-256 fingerprint for a credential.

    The same PAT always produces the same fingerprint, enabling usage
    tracking across audit entries without storing the secret.

    Args:
        secret: The credential value (PAT, API key, etc.).

    Returns:
        First 12 hex characters of the SHA-256 hash, or empty string.
    """
    if not secret:
        return ""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


# ======================================================================
# Log Sanitization
# ======================================================================

def redact_for_log(data: Any, _depth: int = 0) -> Any:
    """Recursively redact sensitive fields in a data structure.

    Sensitive fields are replaced with a partial representation showing
    the first 4 and last 4 characters (e.g., 'eyJh...2bcd'). Output is
    bounded to prevent log bloat.

    Args:
        data: The data structure to sanitize (dict, list, or scalar).
        _depth: Recursion depth guard (internal).

    Returns:
        Sanitized copy of the data.
    """
    if _depth > 10:
        return "[REDACTED: max depth]"

    if isinstance(data, dict):
        result = {}
        count = 0
        for key, value in data.items():
            if count >= _MAX_COLLECTION_SIZE:
                result["_truncated"] = f"{len(data) - count} more items"
                break
            if isinstance(key, str) and key.lower() in _SENSITIVE_FIELDS:
                result[key] = _mask_value(value)
            else:
                result[key] = redact_for_log(value, _depth + 1)
            count += 1
        return result

    if isinstance(data, (list, tuple)):
        items = []
        for i, item in enumerate(data):
            if i >= _MAX_COLLECTION_SIZE:
                items.append(f"[...{len(data) - i} more items]")
                break
            items.append(redact_for_log(item, _depth + 1))
        return items

    if isinstance(data, str) and len(data) > _MAX_STRING_LENGTH:
        return data[:_MAX_STRING_LENGTH] + "...[truncated]"

    if isinstance(data, bytes):
        return f"[BINARY {len(data)} bytes]"

    return data


def _mask_value(value: Any) -> str:
    """Mask a sensitive value, showing first 4 + last 4 chars."""
    if not value:
        return "[EMPTY]"
    s = str(value)
    if len(s) <= 8:
        return "[REDACTED]"
    return f"{s[:4]}...{s[-4:]}"


# ======================================================================
# Audit Entry Writing
# ======================================================================

def _write_audit_entry(collection_name: str, entry: Dict[str, Any]) -> bool:
    """Write an audit entry to DocumentDB.

    Fail-open: if writing fails, set _audit_disabled for the process
    lifetime and log a warning. Tool calls continue unimpeded.

    Args:
        collection_name: Target DocumentDB collection name.
        entry: The audit record to write.

    Returns:
        True if written successfully, False otherwise.
    """
    global _audit_disabled

    if _audit_disabled:
        return False

    try:
        from gateway.config.db import get_db
        db = get_db()
        if db is None:
            logger.warning("[AUDIT] DocumentDB unavailable -- audit write skipped")
            return False

        db[collection_name].insert_one(entry)
        return True
    except Exception as exc:
        logger.error("[AUDIT] DocumentDB audit write failed (disabling audit): %s", exc)
        _audit_disabled = True
        return False


def _build_base_entry(
    tool_name: str,
    status: str,
    duration_ms: float,
    request_data: Dict[str, Any],
    response_summary: Dict[str, Any],
    error_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the base audit entry common to all pipelines.

    Args:
        tool_name: The MCP tool that was invoked.
        status: Outcome status (ok, error, rate_limited, timeout, exception).
        duration_ms: Execution time in milliseconds.
        request_data: Sanitized request parameters.
        response_summary: Extracted outcome fields.
        error_info: Error details (if status != ok).

    Returns:
        Audit entry dict.
    """
    from gateway.middleware.auth import get_current_caller, get_current_jira_pat_source

    caller = get_current_caller()
    caller_identity = caller.to_dict() if caller else {}

    entry: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "caller": caller_identity.get("consumer", "unknown"),
        "caller_identity": caller_identity,
        "status": status,
        "duration_ms": round(duration_ms, 1),
        "request": redact_for_log(request_data),
        "response_summary": response_summary,
        "credential_source": get_current_jira_pat_source(),
    }

    if error_info:
        entry["error"] = error_info

    return entry


# ======================================================================
# Pipeline 1: Jira Audit (@jira_audited)
# ======================================================================

def jira_audited(fn: Callable) -> Callable:
    """Audit decorator for Jira tool functions (Pipeline 1).

    Writes to MCPJiraAudit collection. Captures the full request lifecycle
    including guardrail-blocked calls.

    Usage:
        @jira_audited
        @rate_limited
        def jira_create_issue(summary, project, ...):
            ...
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.time()
        status = "ok"
        result: Any = None
        error_info: Optional[Dict[str, Any]] = None

        try:
            result = fn(*args, **kwargs)

            # Detect rate-limited or guardrail-blocked results
            if isinstance(result, dict):
                if result.get("error") == "rate_limited":
                    status = "rate_limited"
                elif result.get("guardrail"):
                    status = "blocked"
                elif result.get("error"):
                    status = "error"
                    error_info = {"message": result.get("message", "")}

            return result
        except Exception as exc:
            status = "exception"
            error_info = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            duration_ms = (time.time() - start) * 1000
            response_summary = _summarize_result(result) if result else {}

            entry = _build_base_entry(
                tool_name=fn.__name__,
                status=status,
                duration_ms=duration_ms,
                request_data={"args": list(args), "kwargs": kwargs},
                response_summary=response_summary,
                error_info=error_info,
            )
            entry["backend"] = "jira"

            _write_audit_entry(JIRA_AUDIT_COLLECTION, entry)

            # Structured log (secondary audit path for log aggregators)
            logger.info(
                "[JIRA_AUDIT] tool=%s status=%s duration=%.1fms consumer=%s",
                fn.__name__, status, duration_ms,
                entry.get("caller", "unknown"),
            )

    return wrapper


# ======================================================================
# Pipeline 2: Generic Audit (@audit_log)
# ======================================================================

def audit_log(fn: Callable) -> Callable:
    """Audit decorator for non-Jira tools (Pipeline 2).

    Writes to MCPAuditLog collection. Covers BRE, Neo4j, and Teradata tools.

    Usage:
        @audit_log
        @rate_limited
        def neo4j_run_query(query, ...):
            ...
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.time()
        status = "ok"
        result: Any = None
        error_info: Optional[Dict[str, Any]] = None

        try:
            result = fn(*args, **kwargs)

            if isinstance(result, dict):
                if result.get("error") == "rate_limited":
                    status = "rate_limited"
                elif result.get("guardrail"):
                    status = "blocked"
                elif result.get("error"):
                    status = "error"
                    error_info = {"message": result.get("message", "")}

            return result
        except Exception as exc:
            status = "exception"
            error_info = {"type": type(exc).__name__, "message": str(exc)}
            raise
        finally:
            duration_ms = (time.time() - start) * 1000
            response_summary = _summarize_result(result) if result else {}

            entry = _build_base_entry(
                tool_name=fn.__name__,
                status=status,
                duration_ms=duration_ms,
                request_data={"args": list(args), "kwargs": kwargs},
                response_summary=response_summary,
                error_info=error_info,
            )

            _write_audit_entry(GENERIC_AUDIT_COLLECTION, entry)

            logger.info(
                "[AUDIT] tool=%s status=%s duration=%.1fms consumer=%s",
                fn.__name__, status, duration_ms,
                entry.get("caller", "unknown"),
            )

    return wrapper


# ======================================================================
# Pipeline 3: Access Audit (Token Generation)
# ======================================================================

def log_access_audit(
    event_type: str,
    user_id: str,
    success: bool,
    scope: Optional[Dict[str, Any]] = None,
    denial_reason: str = "",
    client_ip: str = "",
    user_agent: str = "",
) -> None:
    """Log a Kiro access audit event (Pipeline 3).

    Every token generation attempt (success or failure) is recorded.

    Args:
        event_type: Event type (e.g., 'token_generation', 'profile_lookup').
        user_id: The user requesting access.
        success: Whether the event succeeded.
        scope: Scope granted (allowed_tools, projects, role) if successful.
        denial_reason: Reason for denial if unsuccessful.
        client_ip: Client IP address.
        user_agent: Client user agent string.
    """
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "user_id": user_id,
        "success": success,
        "scope": scope or {},
        "denial_reason": denial_reason,
        "client_ip": client_ip,
        "user_agent": user_agent,
    }

    _write_audit_entry(KIRO_AUDIT_COLLECTION, entry)

    log_fn = logger.info if success else logger.warning
    log_fn(
        "[ACCESS_AUDIT] event=%s user=%s success=%s reason=%s",
        event_type, user_id, success, denial_reason or "n/a",
    )


# ======================================================================
# Helpers
# ======================================================================

def _summarize_result(result: Any) -> Dict[str, Any]:
    """Extract outcome-relevant fields from a tool result for audit.

    Whitelist-based extraction prevents large payloads in audit records.

    Args:
        result: The tool's return value.

    Returns:
        Summary dict with key outcome fields.
    """
    if not isinstance(result, dict):
        return {}

    summary: Dict[str, Any] = {}
    whitelist = {
        "success", "error", "issue_key", "issue_keys", "bre_id",
        "count", "total", "status", "message",
    }

    for key in whitelist:
        if key in result:
            value = result[key]
            if isinstance(value, (str, int, float, bool)):
                summary[key] = value
            elif isinstance(value, list) and len(value) <= 20:
                summary[key] = value
            elif isinstance(value, list):
                summary[key] = value[:20]
                summary[f"{key}_truncated"] = len(value)

    return summary
