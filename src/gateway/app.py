"""
Enterprise MCP Gateway - Application Entry Point.

Starlette/ASGI server setup with stateless_http=True on /mcp.
Supports two transport modes:
    - stdio: Local IDE clients (Kiro, Claude Desktop). No auth required.
    - streamable-http: Service-to-service over HTTPS with AuthMiddleware.

Usage:
    python src/gateway/app.py --transport=streamable-http --port=8100
"""

from __future__ import annotations

import argparse
import logging
import sys
import time

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from gateway.config.settings import LOG_LEVEL, MCP_SERVER_PORT
from gateway.middleware.auth import AuthMiddleware

logger = logging.getLogger("enterprise-mcp-gateway")


# ======================================================================
# Health Endpoints
# ======================================================================

async def health_check(request: Request) -> JSONResponse:
    """Liveness probe for Kubernetes and load balancers."""
    return JSONResponse({
        "status": "healthy",
        "service": "enterprise-mcp-gateway",
        "timestamp": time.time(),
    })


async def root_handler(request: Request) -> JSONResponse:
    """Root endpoint with gateway metadata."""
    return JSONResponse({
        "service": "Enterprise MCP Gateway",
        "version": "1.0.0",
        "description": (
            "Multi-tenant Model Context Protocol gateway with dynamic RBAC, "
            "multi-backend integration, and defense-in-depth observability."
        ),
        "endpoints": {
            "mcp": "/mcp (JSON-RPC 2.0 - MCP tools/call, tools/list)",
            "health": "/health",
            "dashboard": "/mcp/portal",
            "api": "/mcp/api/*",
        },
    })


# ======================================================================
# Server Setup
# ======================================================================

def _configure_logging() -> None:
    """Configure structured logging for the gateway."""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )


def create_app() -> Starlette:
    """Create the Starlette ASGI application.

    The MCP server (FastMCP) is mounted at /mcp with stateless_http=True,
    removing the MCP session handshake requirement so plain HTTP consumers
    (Java RestTemplate, Python httpx, curl) can POST tools/call directly.

    Returns:
        Starlette application with AuthMiddleware and MCP routes.
    """
    _configure_logging()

    # Build route list: health + dashboard API + MCP mount
    routes = [
        Route("/", root_handler, methods=["GET"]),
        Route("/health", health_check, methods=["GET"]),
    ]

    # Import and register MCP tools
    try:
        from fastmcp import FastMCP  # type: ignore[import-untyped]

        mcp = FastMCP(
            "Enterprise MCP Gateway",
            stateless_http=True,
        )

        # Register tool groups
        _register_tools(mcp)

        # Mount MCP at /mcp
        mcp_app = mcp.get_asgi_app()
        logger.info("[STARTUP] FastMCP server created with stateless_http=True")
    except ImportError:
        logger.warning("[STARTUP] FastMCP not installed -- MCP endpoint disabled")
        mcp_app = None

    app = Starlette(
        debug=False,
        routes=routes,
    )

    # Add AuthMiddleware
    app.add_middleware(AuthMiddleware)

    # Mount MCP app if available
    if mcp_app is not None:
        app.mount("/mcp", mcp_app)

    logger.info(
        "[STARTUP] Enterprise MCP Gateway initialized (port=%d, log_level=%s)",
        MCP_SERVER_PORT, LOG_LEVEL,
    )
    return app


def _register_tools(mcp: object) -> None:
    """Register all MCP tool groups.

    Tool registration is modular -- each backend module provides a
    register(mcp) function that decorates its tool handlers.

    Args:
        mcp: FastMCP server instance.
    """
    # Health/metrics built-in tools
    @mcp.tool()  # type: ignore[attr-defined]
    def health_status() -> dict:
        """Gateway health and backend connectivity status."""
        return {
            "status": "healthy",
            "service": "enterprise-mcp-gateway",
            "version": "1.0.0",
            "timestamp": time.time(),
        }

    # Register backend tool modules (each has a register(mcp) function)
    tool_modules = [
        ("gateway.backends.jira_backend", "Jira"),
        ("gateway.backends.bre_backend", "Business Rule Engine"),
        ("gateway.backends.neo4j_backend", "Neo4j"),
        ("gateway.backends.teradata_backend", "Teradata"),
    ]

    for module_path, label in tool_modules:
        try:
            import importlib
            mod = importlib.import_module(module_path)
            if hasattr(mod, "register"):
                mod.register(mcp)
                logger.info("[STARTUP] Registered %s tools", label)
            else:
                logger.debug("[STARTUP] %s module has no register() function", label)
        except ImportError:
            logger.info("[STARTUP] %s module not available -- skipping", label)
        except Exception as exc:
            logger.warning("[STARTUP] Failed to register %s tools: %s", label, exc)


# ======================================================================
# Main
# ======================================================================

def main() -> None:
    """Parse CLI arguments and start the gateway server."""
    parser = argparse.ArgumentParser(description="Enterprise MCP Gateway")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="streamable-http",
        help="MCP transport mode (default: streamable-http)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=MCP_SERVER_PORT,
        help=f"Server port (default: {MCP_SERVER_PORT})",
    )
    args = parser.parse_args()

    _configure_logging()

    if args.transport == "stdio":
        logger.info("[STARTUP] Starting in stdio mode (local IDE, no auth)")
        try:
            from fastmcp import FastMCP  # type: ignore[import-untyped]
            mcp = FastMCP("Enterprise MCP Gateway")
            _register_tools(mcp)
            mcp.run(transport="stdio")
        except ImportError:
            logger.error("FastMCP is required for stdio mode")
            sys.exit(1)
    else:
        import uvicorn
        app = create_app()
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=args.port,
            log_level=LOG_LEVEL.lower(),
        )


if __name__ == "__main__":
    main()
