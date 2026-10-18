"""
Enterprise MCP Gateway - JWT Validator Unit Tests.

Tests IdP-agnostic JWT validation, claim extraction, and consumer type checks.
"""

import pytest

import gateway.security.jwt_validator as jwt_module
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


# ======================================================================
# Fail-Closed Configuration Gate
# ======================================================================

class TestUnsafeJwtConfiguration:
    """Validation refuses to run on an unsafe algorithm/issuer/audience setup."""

    @pytest.fixture
    def safe_config(self, monkeypatch):
        monkeypatch.setattr(jwt_module, "JWT_AUTH_ENABLED", True)
        monkeypatch.setattr(jwt_module, "JWT_ISSUER", "https://idp.example.com")
        monkeypatch.setattr(jwt_module, "JWT_VERIFY_AUD", True)
        monkeypatch.setattr(jwt_module, "JWT_AUDIENCE", "mcp-gateway")
        monkeypatch.setattr(jwt_module, "JWT_ALGORITHMS", ["HS512"])

    def test_safe_config_passes(self, safe_config):
        assert jwt_module._unsafe_jwt_configuration() == ""

    def test_unsigned_algorithm_rejected(self, safe_config, monkeypatch):
        """A single-entry 'none' list is not a safe single key family."""
        monkeypatch.setattr(jwt_module, "JWT_ALGORITHMS", ["none"])
        assert jwt_module._unsafe_jwt_configuration() != ""

    def test_unrecognized_algorithm_rejected(self, safe_config, monkeypatch):
        monkeypatch.setattr(jwt_module, "JWT_ALGORITHMS", ["HS999"])
        assert jwt_module._unsafe_jwt_configuration() != ""

    def test_empty_algorithm_list_rejected(self, safe_config, monkeypatch):
        monkeypatch.setattr(jwt_module, "JWT_ALGORITHMS", [])
        assert jwt_module._unsafe_jwt_configuration() != ""

    def test_mixed_key_families_rejected(self, safe_config, monkeypatch):
        monkeypatch.setattr(jwt_module, "JWT_ALGORITHMS", ["HS256", "RS256"])
        assert jwt_module._unsafe_jwt_configuration() != ""

    def test_missing_issuer_rejected(self, safe_config, monkeypatch):
        monkeypatch.setattr(jwt_module, "JWT_ISSUER", "")
        assert jwt_module._unsafe_jwt_configuration() != ""

    def test_audience_verification_without_audience_rejected(self, safe_config, monkeypatch):
        monkeypatch.setattr(jwt_module, "JWT_AUDIENCE", "")
        assert jwt_module._unsafe_jwt_configuration() != ""

    def test_unsafe_config_makes_validation_return_none(self, safe_config, monkeypatch):
        monkeypatch.setattr(jwt_module, "JWT_ALGORITHMS", ["none"])
        assert validate_jwt_token("a.b.c") is None
