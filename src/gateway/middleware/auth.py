"""
Enterprise MCP Gateway - Authentication Middleware.

Central ASGI middleware handling all authentication paths:

    Mode 1: API Key + JWT Bearer Token (service-to-service consumers)
    Mode 2: Kiro RBAC (gateway-signed JWT for IDE consumers)
    Mode 3: Kiro Legacy (auto-whitelist, local dev only)

Produces a CallerIdentity stored in request.state and a contextvars.ContextVar
for async-safe downstream access by audit loggers, rate limiters, and guardrails.

Design principles:
    - Single entry point for ALL auth decisions
    - JWT-verified identity overrides header-declared identity (zero-trust)
    - ContextVar propagation for async-safe identity flow
    - Public paths (health, dashboard) bypass auth entirely
"""

from __future__ import annotations

import contextvars
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from gateway.config.settings import (
    JWT_AUTH_ENABLED,
    KIRO_RBAC_ENABLED,
)
from gateway.security.consumer_registry import ConsumerProfile, authenticate
from gateway.security.jwt_validator import (
    JWTClaims,
    is_jwt_required_for_consumer,
    validate_jwt_token,
)

logger = logging.getLogger("enterprise-mcp-gateway.auth")

# Paths that bypass authentication entirely
_PUBLIC_PATHS = frozenset({"/", "/health", "/favicon.ico"})
_PUBLIC_PREFIXES = ("/mcp/portal", "/mcp/dashboard", "/mcp/api/", "/.well-known")


# ======================================================================
# Caller Identity
# ======================================================================

@dataclass
class CallerIdentity:
    """Captures the verified identity of the current request caller.

    Stored in request.state.caller and in a ContextVar for async-safe access
    from audit loggers, rate limiters, and tool handlers.

    Attributes:
        app_name: Application identifier (from X-MCP-App-Name header).
        user_id: Verified user identifier (from JWT or header).
        username: Human-readable display name.
        user_email: Email address.
        consumer: The authenticated ConsumerProfile.
        user_groups: AD/IdP group memberships.
        credential_fingerprint: SHA-256 fingerprint of the credential used.
    """

    app_name: str = ""
    user_id: str = ""
    username: str = ""
    user_email: str = ""
    consumer: Optional[ConsumerProfile] = None
    user_groups: List[str] = field(default_factory=list)
    credential_fingerprint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a dict suitable for audit logging."""
        return {
            "app_name": self.app_name,
            "user_id": self.user_id,
            "username": self.username,
            "user_email": self.user_email,
            "consumer": self.consumer.consumer if self.consumer else "unknown",
            "consumer_type": self.consumer.type if self.consumer else "unknown",
            "user_groups": self.user_groups,
            "credential_fingerprint": self.credential_fingerprint,
        }

    @property
    def caller_label(self) -> str:
        """Short label for structured logging."""
        parts = []
        if self.app_name:
            parts.append(self.app_name)
        if self.user_id:
            parts.append(self.user_id)
        return " / ".join(parts) or "anonymous"


# ======================================================================
# Context Variables (async-safe per-request state)
# ======================================================================

_current_caller_var: contextvars.ContextVar[Optional[CallerIdentity]] = (
    contextvars.ContextVar("current_caller", default=None)
)
_jira_pat_var: contextvars.ContextVar[Optional[str]] = (
    contextvars.ContextVar("jira_pat", default=None)
)
_jira_pat_source_var: contextvars.ContextVar[str] = (
    contextvars.ContextVar("jira_pat_source", default="none")
)


def get_current_caller() -> Optional[CallerIdentity]:
    """Get the current request's caller identity (async-safe)."""
    return _current_caller_var.get()


def get_current_user_pid() -> str:
    """Get the current user's PID/user_id."""
    caller = _current_caller_var.get()
    return caller.user_id if caller else ""


def get_current_jira_pat() -> Optional[str]:
    """Get the Jira PAT for the current request."""
    return _jira_pat_var.get()


def get_current_jira_pat_source() -> str:
    """Get the source of the current Jira PAT (request_header/profile/server_config)."""
    return _jira_pat_source_var.get()


# ======================================================================
# Auth Middleware
# ======================================================================

class AuthMiddleware(BaseHTTPMiddleware):
    """Starlette middleware implementing three-mode authentication.

    Authentication flow:
        1. Public path bypass (health, portal, dashboard API)
        2. Kiro IDE detection (no API key, app name starts with 'kiro-')
           a. KIRO_RBAC_ENABLED=true: Validate X-MCP-Auth-Token (gateway-signed JWT)
           b. KIRO_RBAC_ENABLED=false: Auto-whitelist with wildcard access
        3. API Key authentication from X-MCP-API-Key header
        4. JWT validation for service consumers (when JWT_AUTH_ENABLED=true)
        5. Header extraction for identity fields
        6. Credential resolution (Jira PAT, LLM orchestrator keys)
        7. CallerIdentity construction and ContextVar storage
        8. Cleanup after request completes
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process authentication for every incoming request."""
        path = request.url.path

        # ── Public path bypass ──
        if path in _PUBLIC_PATHS or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # ── Extract common headers ──
        api_key = request.headers.get("x-mcp-api-key")
        app_name = request.headers.get("x-mcp-app-name", "")
        auth_token = request.headers.get("x-mcp-auth-token", "")

        consumer: Optional[ConsumerProfile] = None
        jwt_claims: Optional[JWTClaims] = None
        auth_mode = "none"

        # ── Kiro IDE Detection (no API key, app starts with 'kiro-') ──
        if not api_key and app_name.lower().startswith("kiro-"):
            if KIRO_RBAC_ENABLED:
                # Mode 2: Kiro RBAC -- require gateway-signed token
                if not auth_token:
                    return JSONResponse(
                        status_code=401,
                        content={
                            "error": "kiro_auth_required",
                            "message": (
                                "Kiro IDE access requires authentication. "
                                "Visit the Kiro Access portal to generate a token."
                            ),
                        },
                    )

                kiro_claims = validate_jwt_token(auth_token)
                if kiro_claims is None or not kiro_claims.is_valid:
                    return JSONResponse(
                        status_code=401,
                        content={
                            "error": "kiro_token_invalid",
                            "message": (
                                "Your Kiro access token is invalid or expired. "
                                "Visit the Kiro Access portal to generate a new one."
                            ),
                        },
                    )

                # Build scoped ConsumerProfile from verified JWT claims
                consumer = ConsumerProfile(
                    api_key="",
                    consumer=f"kiro-{kiro_claims.user_id}",
                    type="kiro-ide",
                    allowed_tools=kiro_claims.raw_payload.get("allowed_tools", ["*"]),
                    rate_limit=kiro_claims.raw_payload.get("rate_limit", 15),
                    projects=kiro_claims.raw_payload.get("projects", ["*"]),
                )
                jwt_claims = kiro_claims
                auth_mode = "kiro-rbac"

                logger.info(
                    "[AUTH] Kiro RBAC authenticated: user=%s role=%s tools=%d",
                    kiro_claims.user_id,
                    kiro_claims.raw_payload.get("role", "user"),
                    len(consumer.allowed_tools),
                )
            else:
                # Mode 3: Kiro Legacy -- auto-whitelist (local dev only)
                consumer = ConsumerProfile(
                    api_key="",
                    consumer=f"kiro-{app_name}",
                    type="kiro-ide",
                    allowed_tools=["*"],
                    rate_limit=15,
                    projects=["*"],
                )
                auth_mode = "kiro-legacy"
                logger.debug("[AUTH] Kiro legacy mode (auto-whitelist) for %s", app_name)

        # ── Mode 1: API Key Authentication ──
        elif api_key:
            consumer = authenticate(api_key)
            if consumer is None:
                # Unknown API key but kiro- prefix: auto-whitelist passthrough
                if app_name.lower().startswith("kiro-"):
                    consumer = ConsumerProfile(
                        api_key=api_key,
                        consumer=f"kiro-passthrough-{app_name}",
                        type="kiro-ide",
                        allowed_tools=["*"],
                        rate_limit=15,
                        projects=["*"],
                    )
                    auth_mode = "kiro-passthrough"
                else:
                    return JSONResponse(
                        status_code=401,
                        content={
                            "error": "unauthorized",
                            "message": "Invalid or unregistered API key.",
                        },
                    )
            else:
                auth_mode = "api-key"

        else:
            # No API key and not Kiro: stdio mode (local development)
            consumer = authenticate(None)
            auth_mode = "stdio"

        # ── Extract identity from headers ──
        user_id = request.headers.get("x-mcp-user-id", "")
        username = request.headers.get("x-mcp-username", "")
        user_email = request.headers.get("x-mcp-user-email", "")
        user_groups_raw = request.headers.get("x-mcp-user-groups", "")
        user_groups = [g.strip() for g in user_groups_raw.split(",") if g.strip()]

        # ── JWT validation for service consumers (Mode 1 enhancement) ──
        if consumer and consumer.type != "kiro-ide" and JWT_AUTH_ENABLED:
            bearer = request.headers.get("authorization", "")
            if bearer.lower().startswith("bearer "):
                token = bearer[7:].strip()
                jwt_claims = validate_jwt_token(token)
                if jwt_claims and jwt_claims.is_valid:
                    # JWT-verified identity OVERRIDES header-declared identity
                    user_id = jwt_claims.user_id
                    username = jwt_claims.username
                    user_email = jwt_claims.email
                    user_groups = jwt_claims.groups
                    auth_mode = f"{auth_mode}+jwt"
                    logger.debug(
                        "[AUTH] JWT identity override: %s -> %s", app_name, user_id
                    )
                elif is_jwt_required_for_consumer(consumer.type):
                    return JSONResponse(
                        status_code=401,
                        content={
                            "error": "jwt_required",
                            "message": (
                                f"JWT bearer token is required for consumer type "
                                f"'{consumer.type}'."
                            ),
                        },
                    )
            elif is_jwt_required_for_consumer(consumer.type):
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "jwt_required",
                        "message": (
                            f"Authorization: Bearer <token> header is required for "
                            f"consumer type '{consumer.type}'."
                        ),
                    },
                )

        # ── Kiro RBAC identity override ──
        if jwt_claims and auth_mode.startswith("kiro-rbac"):
            user_id = jwt_claims.user_id
            username = jwt_claims.username
            user_email = jwt_claims.email
            user_groups = jwt_claims.groups

        # ── Credential extraction ──
        jira_pat = request.headers.get("x-mcp-jira-pat", "")
        jira_pat_source = "request_header" if jira_pat else "server_config"

        # ── Build CallerIdentity ──
        from gateway.audit.loggers import secret_fingerprint

        caller = CallerIdentity(
            app_name=app_name,
            user_id=user_id,
            username=username,
            user_email=user_email,
            consumer=consumer,
            user_groups=user_groups,
            credential_fingerprint=secret_fingerprint(jira_pat or api_key or ""),
        )

        # Store in request state and context vars
        request.state.caller = caller
        token_caller = _current_caller_var.set(caller)
        token_pat = _jira_pat_var.set(jira_pat or None)
        token_pat_src = _jira_pat_source_var.set(jira_pat_source)

        logger.info(
            "[AUTH] %s | mode=%s consumer=%s user=%s",
            path, auth_mode,
            consumer.consumer if consumer else "none",
            caller.caller_label,
        )

        try:
            response = await call_next(request)
            return response
        finally:
            # ── Cleanup context vars after request ──
            _current_caller_var.reset(token_caller)
            _jira_pat_var.reset(token_pat)
            _jira_pat_source_var.reset(token_pat_src)
