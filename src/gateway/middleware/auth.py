"""
Enterprise MCP Gateway - Authentication Middleware.

Central ASGI middleware handling all authentication paths:

    Mode 1: API Key + JWT Bearer Token (service-to-service consumers)
    Mode 2: Kiro RBAC (gateway-signed JWT for IDE consumers)
    Mode 3: Kiro Legacy (auto-whitelist) - opt-in, loopback only
            (requires GATEWAY_ALLOW_INSECURE_LOCAL=true AND
            KIRO_RBAC_ENABLED=false AND a loopback peer address)

Implemented as pure ASGI middleware (__init__/__call__ over scope, receive and
send) rather than Starlette's BaseHTTPMiddleware. BaseHTTPMiddleware pumps the
downstream response through an anyio stream and materializes it as a single
response object, which stalls the long-lived streamable-HTTP / SSE responses
the MCP endpoint at /mcp depends on. Pure ASGI forwards every
http.response.body message through untouched, so a chunked or never-ending
stream reaches the client as it is produced.

Produces a CallerIdentity stored in the request scope (readable downstream as
request.state.caller) and in a contextvars.ContextVar for async-safe access by
audit loggers, rate limiters, and guardrails.

Design principles:
    - Single entry point for ALL auth decisions
    - JWT-verified identity overrides header-declared identity (zero-trust)
    - ContextVar propagation for async-safe identity flow
    - Public paths (health, dashboard) bypass auth entirely
    - Never buffer a request or response body on the success path
"""

from __future__ import annotations

import contextvars
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from gateway.config.settings import (
    GATEWAY_ALLOW_INSECURE_LOCAL,
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

# Peer addresses accepted by the local-development escape hatch
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# Any of these headers means the request passed through a proxy, so the peer
# address is the proxy's rather than the original caller's.
_FORWARDING_HEADERS = ("x-forwarded-for", "x-forwarded-host", "x-real-ip", "forwarded")


def _is_loopback_client(request: Request) -> bool:
    """Return True only for an unproxied request from a loopback peer.

    Used to confine the insecure local-development auth path to the machine
    the gateway runs on. Note the limitation: client.host is the immediate TCP
    peer, so a reverse proxy or sidecar on the same host would make a remote
    caller look local. Requests carrying forwarding headers are therefore
    refused, but a proxy that strips those headers cannot be detected here --
    which is why this path also requires the explicit
    GATEWAY_ALLOW_INSECURE_LOCAL opt-in and must stay off in any deployment
    that fronts the gateway with a proxy.
    """
    client = request.client
    if client is None:
        return False
    if any(header in request.headers for header in _FORWARDING_HEADERS):
        return False
    return client.host in _LOOPBACK_HOSTS


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

class AuthMiddleware:
    """Pure ASGI middleware implementing three-mode authentication.

    Deliberately NOT a BaseHTTPMiddleware subclass. BaseHTTPMiddleware wraps
    the downstream app in a task that pumps response messages through an anyio
    memory stream and rebuilds them into one response object; that breaks the
    streamable-HTTP / SSE responses served from /mcp, which must be delivered
    chunk by chunk and can stay open indefinitely. This class forwards scope,
    receive and send straight through, so no body is ever materialized on the
    success path.

    Authentication flow:
        1. Public path bypass (health, portal, dashboard API)
        2. Kiro IDE detection (no API key, app name starts with 'kiro-')
           a. KIRO_RBAC_ENABLED=true (default): Validate X-MCP-Auth-Token
              (gateway-signed JWT); no token or an invalid token means 401
           b. KIRO_RBAC_ENABLED=false: 401 unless GATEWAY_ALLOW_INSECURE_LOCAL
              is explicitly true AND the peer address is loopback
        3. API Key authentication from X-MCP-API-Key header. An unregistered
           key is always a 401 - there is no prefix-based passthrough
        3b. No credential at all is a 401 - there is no anonymous access
        4. JWT validation for service consumers (when JWT_AUTH_ENABLED=true)
        5. Header extraction for identity fields
        6. Credential resolution (Jira PAT, LLM orchestrator keys)
        7. CallerIdentity construction and ContextVar storage
        8. Cleanup after request completes
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process authentication for every incoming HTTP request."""
        # Lifespan and websocket scopes carry no credentials and must reach the
        # downstream app untouched.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Read-only view over the scope: headers, path and client only. The
        # request body is never awaited on the success path, so nothing is
        # buffered ahead of the downstream app.
        request = Request(scope, receive=receive)
        path = request.url.path

        # -- Public path bypass --
        if path in _PUBLIC_PATHS or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            await self.app(scope, receive, send)
            return

        # -- Extract common headers --
        api_key = request.headers.get("x-mcp-api-key")
        app_name = request.headers.get("x-mcp-app-name", "")
        auth_token = request.headers.get("x-mcp-auth-token", "")

        consumer: Optional[ConsumerProfile] = None
        jwt_claims: Optional[JWTClaims] = None
        auth_mode = "none"

        # -- Kiro IDE Detection (no API key, app starts with 'kiro-') --
        if not api_key and app_name.lower().startswith("kiro-"):
            if KIRO_RBAC_ENABLED:
                # Mode 2: Kiro RBAC -- require gateway-signed token
                if not auth_token:
                    response = JSONResponse(
                        status_code=401,
                        content={
                            "error": "kiro_auth_required",
                            "message": (
                                "Kiro IDE access requires authentication. "
                                "Visit the Kiro Access portal to generate a token."
                            ),
                        },
                    )
                    await response(scope, receive, send)
                    return

                kiro_claims = validate_jwt_token(auth_token)
                if kiro_claims is None or not kiro_claims.is_valid:
                    response = JSONResponse(
                        status_code=401,
                        content={
                            "error": "kiro_token_invalid",
                            "message": (
                                "Your Kiro access token is invalid or expired. "
                                "Visit the Kiro Access portal to generate a new one."
                            ),
                        },
                    )
                    await response(scope, receive, send)
                    return

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
            elif GATEWAY_ALLOW_INSECURE_LOCAL and _is_loopback_client(request):
                # Mode 3: Kiro Legacy -- auto-whitelist. Opt-in and loopback
                # only; never reachable from another host.
                consumer = ConsumerProfile(
                    api_key="",
                    consumer=f"kiro-{app_name}",
                    type="kiro-ide",
                    allowed_tools=["*"],
                    rate_limit=15,
                    projects=["*"],
                )
                auth_mode = "kiro-legacy"
                logger.warning(
                    "[AUTH] INSECURE local auto-whitelist used: app=%s client=%s "
                    "(GATEWAY_ALLOW_INSECURE_LOCAL=true)",
                    app_name,
                    request.client.host if request.client else "unknown",
                )
            else:
                response = JSONResponse(
                    status_code=401,
                    content={
                        "error": "kiro_auth_required",
                        "message": (
                            "Kiro IDE access requires an authentication token. "
                            "Visit the Kiro Access portal to generate one."
                        ),
                    },
                )
                await response(scope, receive, send)
                return

        # -- Mode 1: API Key Authentication --
        elif api_key:
            consumer = authenticate(api_key)
            if consumer is None:
                # Unregistered key: always rejected, regardless of app name
                response = JSONResponse(
                    status_code=401,
                    content={
                        "error": "unauthorized",
                        "message": "Invalid or unregistered API key.",
                    },
                )
                await response(scope, receive, send)
                return
            auth_mode = "api-key"

        else:
            # No credential presented: no anonymous access over HTTP
            response = JSONResponse(
                status_code=401,
                content={
                    "error": "unauthorized",
                    "message": "An API key is required. Set the X-MCP-API-Key header.",
                },
            )
            await response(scope, receive, send)
            return

        # -- Extract identity from headers --
        user_id = request.headers.get("x-mcp-user-id", "")
        username = request.headers.get("x-mcp-username", "")
        user_email = request.headers.get("x-mcp-user-email", "")
        user_groups_raw = request.headers.get("x-mcp-user-groups", "")
        user_groups = [g.strip() for g in user_groups_raw.split(",") if g.strip()]

        # -- JWT validation for service consumers (Mode 1 enhancement) --
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
                    response = JSONResponse(
                        status_code=401,
                        content={
                            "error": "jwt_required",
                            "message": (
                                f"JWT bearer token is required for consumer type "
                                f"'{consumer.type}'."
                            ),
                        },
                    )
                    await response(scope, receive, send)
                    return
            elif is_jwt_required_for_consumer(consumer.type):
                response = JSONResponse(
                    status_code=401,
                    content={
                        "error": "jwt_required",
                        "message": (
                            f"Authorization: Bearer <token> header is required for "
                            f"consumer type '{consumer.type}'."
                        ),
                    },
                )
                await response(scope, receive, send)
                return

        # -- Kiro RBAC identity override --
        if jwt_claims and auth_mode.startswith("kiro-rbac"):
            user_id = jwt_claims.user_id
            username = jwt_claims.username
            user_email = jwt_claims.email
            user_groups = jwt_claims.groups

        # -- Credential extraction --
        jira_pat = request.headers.get("x-mcp-jira-pat", "")
        # Used only for write-credential attribution (guardrail 3). It has no
        # effect on rate limiting: no credential source bypasses the limiter.
        jira_pat_source = "request_header" if jira_pat else "server_config"

        # -- Build CallerIdentity --
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

        # Store in request state and context vars. Writing scope["state"]
        # directly is what Starlette's HTTPConnection.state does, so the value
        # stays reachable downstream as request.state.caller.
        scope.setdefault("state", {})["caller"] = caller
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
            await self.app(scope, receive, send)
        finally:
            # -- Cleanup context vars after request --
            _current_caller_var.reset(token_caller)
            _jira_pat_var.reset(token_pat)
            _jira_pat_source_var.reset(token_pat_src)
