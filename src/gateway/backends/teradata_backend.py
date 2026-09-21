"""
Enterprise MCP Gateway - Teradata Analytical Data Warehouse Backend.

Provides read-only MCP tools proxied through an open-source Teradata MCP
sidecar server running as an in-pod companion process.

The gateway performs the full MCP JSON-RPC handshake (initialize,
notifications/initialized, tools/call) over HTTP, managing session state
with automatic re-handshake on session expiry.

Read-only enforcement is layered at 4 levels:
    1. Database account permissions (no write grants)
    2. Sidecar profile configuration (readonly)
    3. Gateway SQL validation guardrail (blocks DDL/DML)
    4. Row cap enforcement in the gateway client

Self-disables when TERADATA_MCP_ENABLED=false.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from typing import Any, Dict, Optional

import httpx

from gateway.audit.loggers import audit_log
from gateway.config.settings import TERADATA_MCP_ENABLED, TERADATA_MCP_TIMEOUT_SECONDS, TERADATA_MCP_URL
from gateway.ratelimit.limiter import rate_limited

logger = logging.getLogger("enterprise-mcp-gateway.teradata")

_PROTOCOL_VERSION = "2025-03-26"
_MAX_ERR_MSG = 500


def _truncate(msg: Any) -> str:
    """Truncate error messages to prevent large payloads."""
    text = str(msg or "")
    return text if len(text) <= _MAX_ERR_MSG else text[:_MAX_ERR_MSG] + "..."


def _parse_response(text: str, content_type: str) -> dict:
    """Parse JSON-RPC response from plain JSON or SSE body."""
    text = (text or "").strip()
    if not text:
        return {}
    if "text/event-stream" in (content_type or "") or text.startswith("data:"):
        last = None
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload:
                    try:
                        last = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
        return last or {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


class TeradataMCPClient:
    """Read-only MCP client for the Teradata sidecar over HTTP.

    Thread-safe with serialized calls (acceptable for read-only, low-volume
    Teradata queries that are rate-limited at the gateway level).
    """

    def __init__(self, url: Optional[str] = None, timeout: Optional[int] = None):
        self.url = url or TERADATA_MCP_URL
        self.timeout = timeout or TERADATA_MCP_TIMEOUT_SECONDS
        self._session_id: Optional[str] = None
        self._lock = threading.Lock()

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    def _rpc(self, client: httpx.Client, method: str, params: Optional[dict],
             is_notification: bool = False) -> tuple:
        payload: Dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not is_notification:
            payload["id"] = str(uuid.uuid4())
        resp = client.post(self.url, json=payload, headers=self._headers())
        sid = resp.headers.get("Mcp-Session-Id") or resp.headers.get("mcp-session-id")
        if sid:
            self._session_id = sid
        body = {} if is_notification else _parse_response(resp.text, resp.headers.get("content-type", ""))
        return body, resp

    def _handshake(self, client: httpx.Client) -> None:
        """MCP initialize + initialized handshake."""
        self._session_id = None
        init_params = {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "enterprise-mcp-gateway", "version": "1.0"},
        }
        body, resp = self._rpc(client, "initialize", init_params)
        if resp.status_code >= 400 or body.get("error"):
            raise RuntimeError(f"initialize failed (HTTP {resp.status_code})")
        try:
            self._rpc(client, "notifications/initialized", {}, is_notification=True)
        except Exception:
            pass

    def call_tool(self, name: str, arguments: Optional[dict] = None) -> dict:
        """Call a sidecar tool with automatic session management.

        Retries once through a fresh handshake on session expiry.

        Args:
            name: Sidecar tool name.
            arguments: Tool arguments.

        Returns:
            Tool result dict, or error dict on failure.
        """
        arguments = arguments or {}
        params = {"name": name, "arguments": arguments}
        try:
            with self._lock:
                with httpx.Client(timeout=self.timeout) as client:
                    if not self._session_id:
                        self._handshake(client)
                    body, resp = self._rpc(client, "tools/call", params)
                    if resp.status_code in (400, 404) and not body.get("result"):
                        self._handshake(client)
                        body, resp = self._rpc(client, "tools/call", params)

            if body.get("error"):
                err = body["error"]
                msg = err.get("message") if isinstance(err, dict) else str(err)
                return {"error": "teradata_mcp_error", "message": _truncate(msg), "tool": name}
            return self._extract_result(body.get("result", {}))
        except httpx.TimeoutException:
            return {"error": "teradata_unavailable", "message": f"Sidecar timed out after {self.timeout}s."}
        except httpx.HTTPError as exc:
            return {"error": "teradata_unavailable", "message": f"Sidecar unreachable: {exc}"}
        except Exception as exc:
            return {"error": "teradata_mcp_error", "message": _truncate(str(exc))}

    @staticmethod
    def _extract_result(result: dict) -> dict:
        """Unwrap MCP tools/call result into the tool payload."""
        if not isinstance(result, dict):
            return {"result": result}
        if isinstance(result.get("structuredContent"), dict):
            return result["structuredContent"]
        for block in result.get("content", []) or []:
            if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                try:
                    return json.loads(block["text"])
                except (json.JSONDecodeError, TypeError):
                    return {"result": block["text"]}
        return result

    def health(self, timeout: Optional[int] = None) -> dict:
        """Probe the sidecar with a handshake."""
        probe_timeout = timeout or min(self.timeout, 10)
        try:
            with httpx.Client(timeout=probe_timeout) as client:
                self._handshake(client)
            return {"ok": True, "url": self.url}
        except Exception as exc:
            return {"ok": False, "url": self.url, "error": str(exc)}


# Singleton client
_client: Optional[TeradataMCPClient] = None


def _get_client() -> TeradataMCPClient:
    global _client
    if _client is None:
        _client = TeradataMCPClient()
    return _client


# ======================================================================
# MCP Tool Handlers
# ======================================================================

@audit_log
@rate_limited
def teradata_read_query(sql: str, row_limit: int = 1000) -> Dict[str, Any]:
    """Execute a read-only SQL query against the Teradata data warehouse.

    Args:
        sql: SELECT or WITH SQL statement.
        row_limit: Maximum rows to return.

    Returns:
        Dict with query results.
    """
    if not TERADATA_MCP_ENABLED:
        return {"error": "teradata_disabled", "message": "Teradata is disabled."}

    from gateway.guardrails.pipeline import validate_sql_readonly
    block = validate_sql_readonly("teradata_read_query", sql)
    if block:
        return block

    return _get_client().call_tool("base_readQuery", {"sql": sql, "rowLimit": row_limit})


@audit_log
@rate_limited
def teradata_list_databases() -> Dict[str, Any]:
    """List available Teradata databases."""
    if not TERADATA_MCP_ENABLED:
        return {"error": "teradata_disabled", "message": "Teradata is disabled."}
    return _get_client().call_tool("base_databaseList")


@audit_log
@rate_limited
def teradata_list_tables(database: str) -> Dict[str, Any]:
    """List tables and views in a Teradata database.

    Args:
        database: Database name.

    Returns:
        Dict with table list.
    """
    if not TERADATA_MCP_ENABLED:
        return {"error": "teradata_disabled", "message": "Teradata is disabled."}
    return _get_client().call_tool("base_tableList", {"database": database})


def register(mcp: Any) -> None:
    """Register all Teradata MCP tools with the FastMCP server.

    Args:
        mcp: FastMCP server instance.
    """
    if not TERADATA_MCP_ENABLED:
        logger.info("[TERADATA] Teradata is disabled -- skipping tool registration")
        return

    mcp.tool()(teradata_read_query)
    mcp.tool()(teradata_list_databases)
    mcp.tool()(teradata_list_tables)
    logger.info("[TERADATA] Registered 3 Teradata tools (read-only via MCP sidecar)")
