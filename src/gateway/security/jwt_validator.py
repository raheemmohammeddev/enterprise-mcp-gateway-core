"""
Enterprise MCP Gateway - IdP-Agnostic JWT Validator.

Validates JWTs from any identity provider through configurable claim field
mapping. The accepted algorithm list is configurable but must stay within a
single key family (HMAC, RSA or EC) so algorithm-confusion attacks are not
possible.

Design principles:
    - Never raises: returns None on any validation failure (safe speculative call)
    - IdP-agnostic: claim field names are configurable, not hardcoded
    - Fail-closed: refuses to validate when the configuration is unsafe
      (no issuer, audience verification without an audience, or algorithms
      spanning multiple key families). The configuration check always runs,
      regardless of JWT_AUTH_ENABLED, because the default-on Kiro RBAC
      (Mode 2) path validates its gateway-signed token through the same
      validate_jwt_token().
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

# Signed algorithms this gateway accepts in JWT_ALGORITHMS. Anything outside
# this allow-list (including 'none') is rejected as an unsafe configuration.
_SUPPORTED_ALGORITHMS = frozenset({
    "HS256", "HS384", "HS512",
    "RS256", "RS384", "RS512",
    "PS256", "PS384", "PS512",
    "ES256", "ES384", "ES512",
})


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


def _algorithm_family(algorithm: str) -> str:
    """Map a JWS algorithm name to its key family.

    Args:
        algorithm: Algorithm name (e.g., 'HS512', 'RS256').

    Returns:
        'hmac', 'rsa', 'ec', or 'unknown'. 'unknown' is always treated as an
        unsafe configuration by _unsafe_jwt_configuration().
    """
    name = (algorithm or "").upper()
    if name.startswith("HS"):
        return "hmac"
    if name.startswith(("RS", "PS")):
        return "rsa"
    if name.startswith("ES"):
        return "ec"
    return "unknown"


def _unsafe_jwt_configuration() -> str:
    """Return a reason string when the JWT configuration is unsafe, else ''.

    Always enforced, independently of JWT_AUTH_ENABLED: the default-on Mode 2
    (Kiro RBAC) path validates its gateway-signed token through the same
    validate_jwt_token(), so gating this check on JWT_AUTH_ENABLED left it
    inert on the shipped configuration. Never includes secrets.
    """
    if not JWT_ISSUER:
        return "JWT_ISSUER is not configured"
    if JWT_VERIFY_AUD and not JWT_AUDIENCE:
        return "JWT_VERIFY_AUD is enabled but JWT_AUDIENCE is empty"
    if not JWT_ALGORITHMS:
        return "JWT_ALGORITHMS is empty"
    unsupported = [
        alg for alg in JWT_ALGORITHMS if (alg or "").upper() not in _SUPPORTED_ALGORITHMS
    ]
    if unsupported:
        return "JWT_ALGORITHMS contains an unsupported algorithm name"
    families = {_algorithm_family(alg) for alg in JWT_ALGORITHMS}
    if "unknown" in families:
        return "JWT_ALGORITHMS contains an algorithm with no recognized key family"
    if len(families) > 1:
        return "JWT_ALGORITHMS spans more than one key family"
    return ""


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

    unsafe = _unsafe_jwt_configuration()
    if unsafe:
        logger.error(
            "[JWT] Refusing to validate tokens with an unsafe configuration: %s", unsafe
        )
        return None

    try:
        from jose import jwt as jose_jwt  # type: ignore[import-untyped]
    except ImportError:
        logger.error("[JWT] python-jose is not installed -- JWT validation unavailable")
        return None

    try:
        # Build decode options
        options: Dict[str, Any] = {
            "verify_signature": True,
            "verify_aud": JWT_VERIFY_AUD,
            "verify_exp": True,
            "verify_iat": True,
            "verify_nbf": True,
            "verify_iss": True,
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
