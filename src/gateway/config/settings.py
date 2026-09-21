"""
Enterprise MCP Gateway - Centralized Configuration.

All settings are loaded from environment variables with sensible defaults.
No proprietary references -- fully vendor-neutral.

Configuration groups:
    - Server: Port, log level, transport
    - DocumentDB: Connection to MongoDB-compatible document store
    - Redis: Distributed cache for response caching and cross-pod coordination
    - JWT Authentication: IdP-agnostic JWT validation for service consumers
    - Kiro RBAC: Gateway-signed token RBAC for IDE consumers
    - Rate Limiting: Per-consumer and per-tool-group sliding-window limits
    - Caching: Response cache TTL and toggle
    - Write Authorization: AD-group-based write permission gates
    - Feature Flags: CI/CD-driven toggles for backend availability
    - Backend Connections: Jira, Neo4j, Teradata, BRE/RDS, SQL Server
    - Encryption: AWS KMS envelope encryption for credential storage
"""

from __future__ import annotations

import os
from typing import List

from dotenv import load_dotenv

load_dotenv()


def _bool(key: str, default: bool = False) -> bool:
    """Read an env var as a boolean (true/1/yes are truthy)."""
    return os.getenv(key, str(default)).lower() in ("true", "1", "yes")


def _int(key: str, default: int) -> int:
    """Read an env var as an integer with a default."""
    try:
        return int(os.getenv(key, str(default)))
    except (ValueError, TypeError):
        return default


def _list(key: str, default: str = "") -> List[str]:
    """Read an env var as a comma-separated list, stripping whitespace."""
    raw = os.getenv(key, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


# ======================================================================
# Server
# ======================================================================
MCP_SERVER_PORT: int = _int("MCP_SERVER_PORT", 8100)
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

# ======================================================================
# DocumentDB (MongoDB-compatible)
# ======================================================================
DOCDB_HOST: str = os.getenv("DOCDB_HOST", "localhost")
DOCDB_PORT: int = _int("DOCDB_PORT", 27017)
DOCDB_USERNAME: str = os.getenv("DOCDB_USERNAME", "")
DOCDB_PASSWORD: str = os.getenv("DOCDB_PASSWORD", "")
DOCDB_DATABASE: str = os.getenv("DOCDB_DATABASE", "ENTERPRISE_MCP_GATEWAY")
DOCDB_TLS_ENABLED: bool = _bool("DOCDB_TLS_ENABLED", False)

# Collection names (vendor-neutral, mcp_ prefix convention)
CONSUMERS_COLLECTION: str = "mcp_consumers"
RBAC_ROLES_COLLECTION: str = "mcp_rbac_roles"
KIRO_PROFILES_COLLECTION: str = "mcp_kiro_profiles"
TOOL_REGISTRY_COLLECTION: str = "mcp_tool_registry"
TOOL_GROUPS_COLLECTION: str = "mcp_tool_groups"
JIRA_PROJECTS_COLLECTION: str = "mcp_jira_projects"
GATEWAY_CONFIG_COLLECTION: str = "mcp_gateway_config"
JIRA_AUDIT_COLLECTION: str = "MCPJiraAudit"
GENERIC_AUDIT_COLLECTION: str = "MCPAuditLog"
KIRO_AUDIT_COLLECTION: str = "MCPKiroAudit"

# ======================================================================
# Redis
# ======================================================================
REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT: int = _int("REDIS_PORT", 6379)
REDIS_SSL: bool = _bool("REDIS_SSL", False)
REDIS_ENABLED: bool = _bool("REDIS_ENABLED", True)

# ======================================================================
# JWT Authentication (Enterprise IdP - IdP-agnostic)
# ======================================================================
JWT_AUTH_ENABLED: bool = _bool("JWT_AUTH_ENABLED", False)
JWT_SECRET: str = os.getenv("JWT_SECRET", "")
JWT_ALGORITHMS: List[str] = _list("JWT_ALGORITHMS", "HS512,HS256,RS256")
JWT_VERIFY_AUD: bool = _bool("JWT_VERIFY_AUD", False)
JWT_AUDIENCE: str = os.getenv("JWT_AUDIENCE", "")
JWT_ISSUER: str = os.getenv("JWT_ISSUER", "")
# IdP-agnostic claim field mapping (comma-separated candidate names)
JWT_CLAIM_USER_ID: str = os.getenv("JWT_CLAIM_USER_ID", "sAMAccountName,sub")
JWT_CLAIM_USERNAME: str = os.getenv("JWT_CLAIM_USERNAME", "preferred_username,name")
JWT_CLAIM_EMAIL: str = os.getenv("JWT_CLAIM_EMAIL", "email")
JWT_CLAIM_GROUPS: str = os.getenv("JWT_CLAIM_GROUPS", "groups,roles")
JWT_REQUIRED_CONSUMER_TYPES: List[str] = _list("JWT_REQUIRED_CONSUMER_TYPES", "ai-agent")

# ======================================================================
# Kiro RBAC (Gateway-signed tokens for IDE consumers)
# ======================================================================
KIRO_RBAC_ENABLED: bool = _bool("KIRO_RBAC_ENABLED", False)
KIRO_TOKEN_TTL_HOURS: int = _int("KIRO_TOKEN_TTL_HOURS", 24)
KIRO_TOKEN_ISSUER: str = os.getenv("KIRO_TOKEN_ISSUER", "enterprise-mcp-gateway")
KIRO_TOKEN_AUDIENCE: str = os.getenv("KIRO_TOKEN_AUDIENCE", "kiro-mcp")

# ======================================================================
# Rate Limiting
# ======================================================================
RATE_LIMIT_WINDOW_SECONDS: int = _int("RATE_LIMIT_WINDOW_SECONDS", 60)
RATE_LIMIT_JIRA: int = _int("RATE_LIMIT_JIRA", 30)
RATE_LIMIT_BRE: int = _int("RATE_LIMIT_BRE", 5)
RATE_LIMIT_NEO4J: int = _int("RATE_LIMIT_NEO4J", 200)
RATE_LIMIT_TERADATA: int = _int("RATE_LIMIT_TERADATA", 20)
RATE_LIMIT_DEFAULT: int = _int("RATE_LIMIT_DEFAULT", 59)
# Write-specific rate limiting
WRITE_RATE_LIMIT: int = _int("WRITE_RATE_LIMIT", 5)
WRITE_RATE_LIMIT_WINDOW: int = _int("WRITE_RATE_LIMIT_WINDOW", 600)

# ======================================================================
# Caching
# ======================================================================
CACHE_ENABLED: bool = _bool("CACHE_ENABLED", True)
CACHE_TTL_SECONDS: int = _int("CACHE_TTL_SECONDS", 300)

# ======================================================================
# Write Authorization
# ======================================================================
USER_WRITE_AUTH_ENABLED: bool = _bool("USER_WRITE_AUTH_ENABLED", True)
WRITE_AD_GROUPS: List[str] = _list("WRITE_AD_GROUPS", "Platform-Admin,Platform-Write-Dev")

# ======================================================================
# Feature Flags
# ======================================================================
NEO4J_ENABLED: bool = _bool("NEO4J_ENABLED", True)
TERADATA_MCP_ENABLED: bool = _bool("TERADATA_MCP_ENABLED", True)

# ======================================================================
# Jira (Project Management Backend)
# ======================================================================
JIRA_BASE_URL: str = os.getenv("JIRA_BASE_URL", "https://jira.example.com")
JIRA_PAT: str = os.getenv("JIRA_PAT", "")
JIRA_BACKEND: str = os.getenv("JIRA_BACKEND", "pat")  # pat | basic | llm-orchestrator

# ======================================================================
# Neo4j (Knowledge Graph Backend)
# ======================================================================
NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USERNAME: str = os.getenv("NEO4J_USERNAME", "neo4j")
NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "")
NEO4J_TIMEOUT_SECONDS: int = _int("NEO4J_TIMEOUT_SECONDS", 20)

# ======================================================================
# Teradata (Analytical Data Warehouse via MCP Sidecar)
# ======================================================================
TERADATA_MCP_URL: str = os.getenv("TERADATA_MCP_URL", "http://localhost:8001/mcp")
TERADATA_MCP_TIMEOUT_SECONDS: int = _int("TERADATA_MCP_TIMEOUT_SECONDS", 30)

# ======================================================================
# Enterprise LLM Orchestrator
# ======================================================================
LLM_ORCHESTRATOR_URL: str = os.getenv("LLM_ORCHESTRATOR_URL", "")
LLM_ORCHESTRATOR_API_KEY: str = os.getenv("LLM_ORCHESTRATOR_API_KEY", "")

# ======================================================================
# AWS KMS Envelope Encryption
# ======================================================================
ENCRYPTION_ENABLED: bool = _bool("ENCRYPTION_ENABLED", False)
KMS_KEY_ID: str = os.getenv("KMS_KEY_ID", "alias/enterprise-mcp-gateway-tokens")
AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")

# ======================================================================
# Tool Registry
# ======================================================================
TOOL_REGISTRY_TTL_SECONDS: int = _int("TOOL_REGISTRY_TTL_SECONDS", 300)
