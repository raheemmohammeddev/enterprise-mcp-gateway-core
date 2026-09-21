"""
Enterprise MCP Gateway - Rate Limiter Unit Tests.

Tests the two-layer sliding-window rate limiter covering per-consumer
(Layer 1) and per-tool-group global (Layer 2) enforcement.
"""

import time

import pytest

from gateway.ratelimit.limiter import (
    _check_consumer_rate_limit,
    _consumer_timestamps,
    _call_timestamps,
    _record_call,
    check_rate_limit,
    _get_group_for_tool,
)


@pytest.fixture(autouse=True)
def clear_rate_state():
    """Clear all rate-limit state between tests."""
    _consumer_timestamps.clear()
    _call_timestamps.clear()
    yield
    _consumer_timestamps.clear()
    _call_timestamps.clear()


# ======================================================================
# Tool-to-Group Mapping
# ======================================================================

class TestToolGroupMapping:
    def test_jira_tools(self):
        assert _get_group_for_tool("jira_create_issue") == "jira"
        assert _get_group_for_tool("get_jira_issues") == "jira"

    def test_bre_tools(self):
        assert _get_group_for_tool("bre_get_details") == "bre"
        assert _get_group_for_tool("bre_search") == "bre"

    def test_neo4j_tools(self):
        assert _get_group_for_tool("neo4j_run_query") == "neo4j"

    def test_teradata_tools(self):
        assert _get_group_for_tool("teradata_read_query") == "teradata"

    def test_unknown_tool(self):
        assert _get_group_for_tool("some_unknown_tool") == "default"


# ======================================================================
# Layer 1: Per-Consumer Rate Limit
# ======================================================================

class TestConsumerRateLimit:
    def test_under_limit_passes(self):
        result = _check_consumer_rate_limit("consumer-a", "jira", 5)
        assert result is None

    def test_at_limit_blocks(self):
        # Fill up the limit
        key = "consumer-block:jira"
        _consumer_timestamps[key] = [time.time() for _ in range(5)]

        result = _check_consumer_rate_limit("consumer-block", "jira", 5)
        assert result is not None
        assert result["error"] == "rate_limited"
        assert result["limit_type"] == "consumer"
        assert result["retry_after_seconds"] > 0

    def test_expired_timestamps_pruned(self):
        """Timestamps outside the window should be pruned."""
        key = "consumer-prune:jira"
        old_time = time.time() - 120  # 2 minutes ago (outside 60s window)
        _consumer_timestamps[key] = [old_time] * 10

        result = _check_consumer_rate_limit("consumer-prune", "jira", 5)
        assert result is None
        # Old timestamps should have been pruned
        assert len(_consumer_timestamps[key]) == 0

    def test_high_limit_passes(self):
        """Admin with rate_limit=30 should not be blocked by 5 calls."""
        key = "admin-consumer:jira"
        _consumer_timestamps[key] = [time.time() for _ in range(5)]

        result = _check_consumer_rate_limit("admin-consumer", "jira", 30)
        assert result is None


# ======================================================================
# Layer 2: Global Per-Tool-Group Rate Limit
# ======================================================================

class TestGlobalRateLimit:
    def test_under_limit_passes(self):
        result = check_rate_limit("jira")
        assert result is None

    def test_at_limit_blocks(self):
        # Fill up the global jira limit (default 30)
        _call_timestamps["jira"] = [time.time() for _ in range(30)]

        result = check_rate_limit("jira")
        assert result is not None
        assert result["error"] == "rate_limited"
        assert result["limit_type"] == "global"

    def test_different_groups_independent(self):
        """Rate limits for different groups are independent."""
        _call_timestamps["jira"] = [time.time() for _ in range(30)]

        # Neo4j should still be fine
        result = check_rate_limit("neo4j")
        assert result is None


# ======================================================================
# Recording
# ======================================================================

class TestRecording:
    def test_record_call_updates_both_stores(self):
        _record_call("jira", "test-consumer")

        assert len(_call_timestamps["jira"]) == 1
        assert len(_consumer_timestamps["test-consumer:jira"]) == 1

    def test_multiple_records_accumulate(self):
        for _ in range(5):
            _record_call("neo4j", "test-consumer")

        assert len(_call_timestamps["neo4j"]) == 5
        assert len(_consumer_timestamps["test-consumer:neo4j"]) == 5
