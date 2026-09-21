"""
Enterprise MCP Gateway - IdP-Agnostic JWT Validator.

Validates JWTs from any identity provider through configurable claim field
mapping. Supports multiple signing algorithms (HS512, HS256, RS256) to enable
gradual migration between IdPs without code changes.

Design principles:
    - Never raises: returns None on any validation failure (safe speculative call)
    - IdP-agnostic: claim field names are configurable, not hardcoded
    - Multi-algorithm: negotiates HS512, HS256, RS256 simultaneously
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from gateway.config.settings import (
    JWT_ALGORITHMS,
    JWT_AUDIENCE,
    JWT_AUTH_ENABLED,
    JWT_CLAIM_EMAIL,
    JWT_CLAIM_GROUPS,
    JWT_CLAIM_USER_ID,
    JWT_CLAIM_USERNAME,
    JWT_ISSUER,
    JWT_REQUIRED_CONSUMER_TYPES,
    JWT_SECRET,
    JWT_VERIFY_AUD,
)

logger = logging.getLogger("enterprise-mcp-gateway.jwt")


@dataclass
class JWTClaims:
    """Normalized view of verified JWT claims, regardless of IdP source.

    Attributes:
        user_id: The authenticated user's unique identifier.
        username: Human-readable display name.
        email: Email address.
        groups: List of AD/IdP group memberships.
        raw_payload: Full decoded JWT payload for access to non-standard claims.
    """

    user_id: str = ""
    username: str = ""
    email: str = ""
    groups: List[str] = field(default_factory=list)
    raw_payload: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        """A claim set is valid if it has a non-empty user_id."""
        return bool(self.user_id)


def _extract_claim(payload: Dict[str, Any], candidate_keys: str) -> str:
    """Extract the first non-empty value from comma-separated candidate keys.

    This makes the validator IdP-agnostic: different IdPs use different claim
    field names (e.g., 'sAMAccountName' vs 'sub' vs 'preferred_username').

    Args:
        payload: Decoded JWT payload dictionary.
        candidate_keys: Comma-separated field names to try in order.

    Returns:
        The first non-empty string value found, or empty string.
    """
    for key in candidate_keys.split(","):
        key = key.strip()
        value = payload.get(key)
        if value and isinstance(value, str):
            return value
    return ""


def _extract_groups(payload: Dict[str, Any], candidate_keys: str) -> List[str]:
    """Extract group membership from JWT payload.

    Supports both list claims and comma-separated string claims.

    Args:
        payload: Decoded JWT payload dictionary.
        candidate_keys: Comma-separated field names to try in order.

    Returns:
        List of group name strings.
    """
    for key in candidate_keys.split(","):
        key = key.strip()
        value = payload.get(key)
        if value is None:
            continue
        if isinstance(value, list):
            return [str(g) for g in value if g]
        if isinstance(value, str) and value:
            return [g.strip() for g in value.split(",") if g.strip()]
    return []


def validate_jwt_token(token: str) -> Optional[JWTClaims]:
    """Validate a JWT token and extract normalized claims.

    Never raises -- returns None on any failure (expired, bad signature,
    missing secret, library not installed, etc.). This makes it safe to
    call speculatively without try/except at every call site.

    Args:
        token: The raw JWT string (without 'Bearer ' prefix).

    Returns:
        JWTClaims with verified identity, or None on any failure.
    """
    if not token:
        return None

    if not JWT_SECRET:
        logger.error("[JWT] JWT_SECRET is not configured -- cannot validate tokens")
        return None

    try:
        from jose import jwt as jose_jwt  # type: ignore[import-untyped]
    except ImportError:
        logger.error("[JWT] python-jose is not installed -- JWT validation unavailable")
        return None

    try:
        # Build decode options
        options: Dict[str, Any] = {
            "verify_aud": JWT_VERIFY_AUD,
            "verify_exp": True,
            "verify_iat": True,
        }

        decode_kwargs: Dict[str, Any] = {
            "token": token,
            "key": JWT_SECRET,
            "algorithms": JWT_ALGORITHMS,
            "options": options,
        }

        if JWT_VERIFY_AUD and JWT_AUDIENCE:
            decode_kwargs["audience"] = JWT_AUDIENCE
        if JWT_ISSUER:
            decode_kwargs["issuer"] = JWT_ISSUER

        payload = jose_jwt.decode(**decode_kwargs)

        # Extract claims using configurable field mapping
        claims = JWTClaims(
            user_id=_extract_claim(payload, JWT_CLAIM_USER_ID),
            username=_extract_claim(payload, JWT_CLAIM_USERNAME),
            email=_extract_claim(payload, JWT_CLAIM_EMAIL),
            groups=_extract_groups(payload, JWT_CLAIM_GROUPS),
            raw_payload=payload,
        )

        if not claims.is_valid:
            logger.warning("[JWT] Token decoded but no user_id found in claims")
            return None

        logger.debug("[JWT] Token validated: user=%s groups=%d", claims.user_id, len(claims.groups))
        return claims

    except Exception as exc:
        logger.warning("[JWT] Token validation failed: %s", exc)
        return None


def is_jwt_required_for_consumer(consumer_type: str) -> bool:
    """Check if a JWT bearer token is required for the given consumer type.

    JWT is required only when JWT_AUTH_ENABLED=true AND the consumer type
    is in JWT_REQUIRED_CONSUMER_TYPES. Kiro IDE, stdio, developer, and
    rest-api consumers are excluded by default.

    Args:
        consumer_type: The consumer's type string (e.g., 'ai-agent', 'kiro-ide').

    Returns:
        True if a valid JWT must be presented.
    """
    if not JWT_AUTH_ENABLED:
        return False
    return consumer_type in JWT_REQUIRED_CONSUMER_TYPES
