"""
Enterprise MCP Gateway - Two-Layer Sliding-Window Rate Limiter.

Protects both individual consumers and shared backend systems via
two independent enforcement layers:

    Layer 1 (inner): Per-consumer limit from RBAC role (e.g., 15/min)
    Layer 2 (outer): Per-tool-group global limit from config (e.g., 59/min for Jira)

Formal algorithm (LaTeX-aligned sliding window):

    N_window(t) = C_current + C_previous * (1 - (t - t_start) / T)  <=  L

Where:
    N_window(t)  = weighted request count at evaluation time t
    C_current    = requests in current window partition
    C_previous   = requests in preceding window partition
    t_start      = start of current window
    T            = window duration (default 60s)
    L            = rate limit threshold

Implementation uses exact per-request timestamps for precise sliding-window
semantics rather than bucketed approximation.

Intelligent bypass: user-provided credentials (PAT, LLM orchestrator key)
skip rate limiting -- they consume their own API quota, not the gateway's.

Design principles:
    - Fail-open: returns cached/empty limits if config store unavailable
    - Two independent layers both must pass
    - Structured error responses with retry_after_seconds
"""

from __future__ import annotations

import functools
import logging
import time
import threading
from typing import Any, Callable, Dict, List, Optional

from gateway.config.settings import (
    RATE_LIMIT_BRE,
    RATE_LIMIT_DEFAULT,
    RATE_LIMIT_JIRA,
    RATE_LIMIT_NEO4J,
    RATE_LIMIT_TERADATA,
    RATE_LIMIT_WINDOW_SECONDS,
)

logger = logging.getLogger("enterprise-mcp-gateway.ratelimit")

# In-memory sliding window stores
_call_timestamps: Dict[str, List[float]] = {}      # group -> [timestamps]
_consumer_timestamps: Dict[str, List[float]] = {}   # consumer:group -> [timestamps]
_lock = threading.Lock()

# Tool group rate limits (configurable via DocumentDB in production)
_GROUP_LIMITS: Dict[str, int] = {
    "jira": RATE_LIMIT_JIRA,
    "bre": RATE_LIMIT_BRE,
    "neo4j": RATE_LIMIT_NEO4J,
    "teradata": RATE_LIMIT_TERADATA,
}


def _get_rate_limit_for_group(group: str) -> int:
    """Get the rate limit for a tool group.

    In production, this would query DocumentDB's mcp_tool_groups collection
    with a TTL cache. Here we use the config-loaded defaults.

    Args:
        group: Tool group key (jira, bre, neo4j, teradata).

    Returns:
        Maximum calls per window for this group.
    """
    return _GROUP_LIMITS.get(group, RATE_LIMIT_DEFAULT)


def _get_group_for_tool(tool_name: str) -> str:
    """Map a tool name to its rate-limit group.

    Args:
        tool_name: The MCP tool name.

    Returns:
        Group key string.
    """
    name = tool_name.lower()
    if name.startswith("jira_") or name.startswith("get_jira"):
        return "jira"
    if name.startswith("bre_"):
        return "bre"
    if name.startswith("neo4j_"):
        return "neo4j"
    if name.startswith("teradata_"):
        return "teradata"
    return "default"


def _get_consumer_rate_limit() -> Optional[int]:
    """Get the current consumer's rate_limit from the auth middleware context.

    Returns the consumer's rate_limit field, or None if not available.
    """
    try:
        from gateway.middleware.auth import get_current_caller
        caller = get_current_caller()
        if caller and caller.consumer:
            return caller.consumer.rate_limit
    except Exception:
        pass
    return None


def _get_consumer_id() -> str:
    """Get the current consumer's identifier for per-consumer tracking."""
    try:
        from gateway.middleware.auth import get_current_caller
        caller = get_current_caller()
        if caller and caller.consumer:
            return caller.consumer.consumer
    except Exception:
        pass
    return "local"


def _is_user_credential_request() -> bool:
    """Check if the current request uses a user-provided credential.

    When a caller provides their own PAT or LLM orchestrator key, rate
    limiting is bypassed -- they consume their own API quota.

    Returns:
        True if the credential source is 'request_header' or 'profile'.
    """
    try:
        from gateway.middleware.auth import get_current_jira_pat_source
        source = get_current_jira_pat_source()
        return source in ("request_header", "profile")
    except Exception:
        return False


# ======================================================================
# Layer 1: Per-Consumer Rate Limiting
# ======================================================================

def _check_consumer_rate_limit(
    consumer_id: str, group: str, consumer_limit: int
) -> Optional[Dict[str, Any]]:
    """Check the per-consumer rate limit (Layer 1 / inner layer).

    Uses exact sliding-window semantics with per-request timestamps:

        timestamps[key] = [ts for ts in timestamps[key] if ts > now - T]
        if len(timestamps[key]) >= L:
            return RATE_LIMITED

    Args:
        consumer_id: The consumer's identifier.
        group: Tool group key.
        consumer_limit: Maximum calls per window for this consumer.

    Returns:
        Error dict with retry_after if exceeded, None if OK.
    """
    now = time.time()
    window = RATE_LIMIT_WINDOW_SECONDS
    key = f"{consumer_id}:{group}"

    if key not in _consumer_timestamps:
        _consumer_timestamps[key] = []

    # Prune timestamps outside the sliding window
    _consumer_timestamps[key] = [
        ts for ts in _consumer_timestamps[key] if ts > now - window
    ]

    if len(_consumer_timestamps[key]) >= consumer_limit:
        wait = int(window - (now - _consumer_timestamps[key][0])) + 1
        return {
            "error": "rate_limited",
            "group": group,
            "consumer": consumer_id,
            "message": (
                f"Consumer rate limit reached ({consumer_limit} calls / {window}s) for "
                f"'{consumer_id}' on '{group}' tools. "
                f"Please wait {wait} seconds before retrying."
            ),
            "retry_after_seconds": wait,
            "limit_type": "consumer",
        }

    return None


# ======================================================================
# Layer 2: Global Per-Tool-Group Rate Limiting
# ======================================================================

def check_rate_limit(group: str) -> Optional[Dict[str, Any]]:
    """Check the global per-group rate limit (Layer 2 / outer layer).

    Args:
        group: Tool group key.

    Returns:
        Error dict with retry_after if exceeded, None if OK.
    """
    now = time.time()
    max_calls = _get_rate_limit_for_group(group)
    window = RATE_LIMIT_WINDOW_SECONDS

    if group not in _call_timestamps:
        _call_timestamps[group] = []

    # Prune timestamps outside the sliding window
    _call_timestamps[group] = [
        ts for ts in _call_timestamps[group] if ts > now - window
    ]

    if len(_call_timestamps[group]) >= max_calls:
        wait = int(window - (now - _call_timestamps[group][0])) + 1
        return {
            "error": "rate_limited",
            "group": group,
            "message": (
                f"Global rate limit reached ({max_calls} calls / {window}s) for '{group}' tools. "
                f"Please wait {wait} seconds before retrying."
            ),
            "retry_after_seconds": wait,
            "limit_type": "global",
        }

    return None


# ======================================================================
# Recording
# ======================================================================

def _record_call(group: str, consumer_id: str) -> None:
    """Record a successful call in both global and consumer tracking."""
    now = time.time()
    _call_timestamps.setdefault(group, []).append(now)
    key = f"{consumer_id}:{group}"
    _consumer_timestamps.setdefault(key, []).append(now)


# ======================================================================
# Decorator
# ======================================================================

def rate_limited(fn: Callable) -> Callable:
    """Decorator that enforces two-layer sliding-window rate limiting.

    Layer 1 (inner): Per-consumer limit from the consumer's RBAC profile
    Layer 2 (outer): Per-tool-group limit from gateway configuration

    Both layers must pass for the call to proceed. Rate limiting is skipped
    when the caller provides their own credential (user PAT or LLM key),
    since those calls consume the user's own quota.

    Usage:
        @rate_limited
        def my_tool_handler(arg1, arg2):
            ...
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        # Skip rate limiting for user-credential requests
        if _is_user_credential_request():
            logger.debug("[RATE_SKIP] tool=%s -- user-provided credential, bypassing", fn.__name__)
            start = time.time()
            result = fn(*args, **kwargs)
            duration_ms = (time.time() - start) * 1000
            logger.info("[CALL] tool=%s group=user_cred duration=%.1fms", fn.__name__, duration_ms)
            return result

        group = _get_group_for_tool(fn.__name__)
        consumer_id = _get_consumer_id()

        with _lock:
            # Layer 1: Per-consumer rate limit
            consumer_limit = _get_consumer_rate_limit()
            if consumer_limit is not None:
                consumer_result = _check_consumer_rate_limit(consumer_id, group, consumer_limit)
                if consumer_result:
                    logger.warning(
                        "[RATE_LIMITED] tool=%s group=%s consumer=%s (consumer limit: %d)",
                        fn.__name__, group, consumer_id, consumer_limit,
                    )
                    return consumer_result

            # Layer 2: Global tool-group rate limit
            group_result = check_rate_limit(group)
            if group_result:
                logger.warning(
                    "[RATE_LIMITED] tool=%s group=%s (global limit)", fn.__name__, group
                )
                return group_result

            # Both passed -- record the call
            _record_call(group, consumer_id)

        start = time.time()
        result = fn(*args, **kwargs)
        duration_ms = (time.time() - start) * 1000

        logger.info(
            "[CALL] tool=%s group=%s consumer=%s duration=%.1fms",
            fn.__name__, group, consumer_id, duration_ms,
        )
        return result

    return wrapper
