"""
Enterprise MCP Gateway - Audit Logger Unit Tests.

Tests credential fingerprinting, log sanitization, and result summarization.
"""

import pytest

from gateway.audit.loggers import (
    _summarize_result,
    redact_for_log,
    secret_fingerprint,
)


# ======================================================================
# Credential Fingerprinting
# ======================================================================

class TestSecretFingerprint:
    def test_consistent_hash(self):
        """Same input always produces the same fingerprint."""
        fp1 = secret_fingerprint("my-secret-pat-token")
        fp2 = secret_fingerprint("my-secret-pat-token")
        assert fp1 == fp2
        assert len(fp1) == 12  # First 12 hex chars of SHA-256

    def test_different_secrets_different_fingerprints(self):
        fp1 = secret_fingerprint("secret-1")
        fp2 = secret_fingerprint("secret-2")
        assert fp1 != fp2

    def test_empty_returns_empty(self):
        assert secret_fingerprint("") == ""

    def test_hex_characters_only(self):
        fp = secret_fingerprint("test-token")
        assert all(c in "0123456789abcdef" for c in fp)


# ======================================================================
# Log Sanitization
# ======================================================================

class TestRedactForLog:
    def test_redacts_sensitive_keys(self):
        data = {"username": "john", "password": "supersecret123", "data": "visible"}
        result = redact_for_log(data)
        assert result["username"] == "john"
        assert "supersecret" not in str(result["password"])
        assert result["data"] == "visible"

    def test_redacts_token_key(self):
        data = {"token": "eyJhbGciOiJIUzI1NiJ9.long-payload.signature"}
        result = redact_for_log(data)
        assert "eyJh" in result["token"]     # First 4 chars shown
        assert "ture" in result["token"]      # Last 4 chars shown
        assert "long-payload" not in result["token"]

    def test_redacts_api_key(self):
        data = {"api_key": "abcdef12345678"}
        result = redact_for_log(data)
        assert result["api_key"] == "abcd...5678"

    def test_nested_dict_redaction(self):
        data = {"outer": {"secret": "hidden-value-here"}}
        result = redact_for_log(data)
        assert "hidden" not in str(result["outer"]["secret"])

    def test_list_redaction(self):
        data = [{"password": "secret123"}, "plain-text"]
        result = redact_for_log(data)
        assert "secret" not in str(result[0]["password"])
        assert result[1] == "plain-text"

    def test_long_string_truncation(self):
        data = {"message": "x" * 600}
        result = redact_for_log(data)
        assert len(result["message"]) < 600
        assert "truncated" in result["message"]

    def test_bytes_handled(self):
        data = {"file": b"\x00\x01\x02\x03"}
        result = redact_for_log(data)
        assert "BINARY" in result["file"]

    def test_short_secret_fully_redacted(self):
        data = {"pat": "abc"}
        result = redact_for_log(data)
        assert result["pat"] == "[REDACTED]"

    def test_empty_value_handled(self):
        data = {"token": ""}
        result = redact_for_log(data)
        assert result["token"] == "[EMPTY]"

    def test_large_collection_truncated(self):
        data = {f"key_{i}": i for i in range(100)}
        result = redact_for_log(data)
        assert "_truncated" in result


# ======================================================================
# Result Summarization
# ======================================================================

class TestSummarizeResult:
    def test_extracts_whitelisted_fields(self):
        result = {"success": True, "issue_key": "PROJ-123", "internal_data": "big-blob"}
        summary = _summarize_result(result)
        assert summary["success"] is True
        assert summary["issue_key"] == "PROJ-123"
        assert "internal_data" not in summary

    def test_truncates_long_lists(self):
        result = {"issue_keys": [f"PROJ-{i}" for i in range(50)]}
        summary = _summarize_result(result)
        assert len(summary["issue_keys"]) == 20
        assert summary["issue_keys_truncated"] == 50

    def test_non_dict_returns_empty(self):
        assert _summarize_result("string-result") == {}
        assert _summarize_result(None) == {}
        assert _summarize_result(42) == {}

    def test_error_field_extracted(self):
        result = {"error": "jira_timeout", "message": "Request timed out"}
        summary = _summarize_result(result)
        assert summary["error"] == "jira_timeout"
        assert summary["message"] == "Request timed out"
