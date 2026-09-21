"""
Enterprise MCP Gateway - JWT Validator Unit Tests.

Tests IdP-agnostic JWT validation, claim extraction, and consumer type checks.
"""

import pytest

from gateway.security.jwt_validator import (
    JWTClaims,
    _extract_claim,
    _extract_groups,
    is_jwt_required_for_consumer,
    validate_jwt_token,
)


# ======================================================================
# JWTClaims Dataclass
# ======================================================================

class TestJWTClaims:
    def test_valid_claims(self):
        claims = JWTClaims(user_id="jdoe", username="John Doe", email="jdoe@example.com")
        assert claims.is_valid is True

    def test_empty_user_id_invalid(self):
        claims = JWTClaims(user_id="", username="John")
        assert claims.is_valid is False

    def test_default_values(self):
        claims = JWTClaims()
        assert claims.user_id == ""
        assert claims.groups == []
        assert claims.raw_payload == {}
        assert claims.is_valid is False


# ======================================================================
# Claim Extraction (IdP-Agnostic)
# ======================================================================

class TestExtractClaim:
    def test_first_candidate_found(self):
        payload = {"sAMAccountName": "jdoe", "sub": "alternate"}
        result = _extract_claim(payload, "sAMAccountName,sub")
        assert result == "jdoe"

    def test_fallback_to_second_candidate(self):
        payload = {"sub": "jdoe"}
        result = _extract_claim(payload, "sAMAccountName,sub")
        assert result == "jdoe"

    def test_no_match_returns_empty(self):
        payload = {"other_field": "value"}
        result = _extract_claim(payload, "sAMAccountName,sub")
        assert result == ""

    def test_empty_value_skipped(self):
        payload = {"sAMAccountName": "", "sub": "fallback"}
        result = _extract_claim(payload, "sAMAccountName,sub")
        assert result == "fallback"

    def test_whitespace_in_candidates(self):
        payload = {"sub": "jdoe"}
        result = _extract_claim(payload, " sub , name ")
        assert result == "jdoe"


# ======================================================================
# Group Extraction
# ======================================================================

class TestExtractGroups:
    def test_list_groups(self):
        payload = {"groups": ["Admin", "Developer"]}
        result = _extract_groups(payload, "groups,roles")
        assert result == ["Admin", "Developer"]

    def test_comma_separated_groups(self):
        payload = {"roles": "Admin, Developer, Reader"}
        result = _extract_groups(payload, "groups,roles")
        assert result == ["Admin", "Developer", "Reader"]

    def test_fallback_key(self):
        payload = {"roles": ["Admin"]}
        result = _extract_groups(payload, "groups,roles")
        assert result == ["Admin"]

    def test_no_groups(self):
        payload = {}
        result = _extract_groups(payload, "groups,roles")
        assert result == []

    def test_empty_list(self):
        payload = {"groups": []}
        result = _extract_groups(payload, "groups,roles")
        assert result == []


# ======================================================================
# Token Validation
# ======================================================================

class TestValidateJwtToken:
    def test_empty_token_returns_none(self):
        assert validate_jwt_token("") is None

    def test_invalid_token_returns_none(self):
        """Malformed tokens return None without raising."""
        assert validate_jwt_token("not.a.valid.jwt.token") is None


# ======================================================================
# Consumer Type Check
# ======================================================================

class TestIsJwtRequired:
    def test_disabled_returns_false(self):
        """When JWT_AUTH_ENABLED=false, JWT is never required."""
        # Default in test env is False
        assert is_jwt_required_for_consumer("ai-agent") is False
        assert is_jwt_required_for_consumer("developer") is False

    def test_kiro_ide_never_required(self):
        """kiro-ide consumers use gateway-signed tokens, not IdP JWTs."""
        assert is_jwt_required_for_consumer("kiro-ide") is False
