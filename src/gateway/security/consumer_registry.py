"""
Enterprise MCP Gateway - Consumer Registry and Authorization.

Manages authenticated consumer profiles with multi-source loading:
    1. DocumentDB (production source of truth)
    2. Local file fallback (development)

Each ConsumerProfile defines what tools and projects a consumer can access,
their rate limit, and their consumer type.

Design: Graceful 2-tier degradation (DocumentDB -> local file -> defaults).
"""

from __future__ import annotations

import json
import logging
import os
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from gateway.config.settings import CONSUMERS_COLLECTION, DOCDB_DATABASE

logger = logging.getLogger("enterprise-mcp-gateway.consumer-registry")

# Cache TTL for the consumer registry (seconds)
_REGISTRY_CACHE_TTL = 300
_registry_cache: Dict[str, "ConsumerProfile"] = {}
_registry_loaded_at: float = 0.0
_registry_lock = threading.Lock()


@dataclass
class ConsumerProfile:
    """Represents an authenticated API consumer with scoped permissions.

    Attributes:
        api_key: The consumer's API key (hashed or partial for logging).
        consumer: Human-readable consumer name.
        type: Consumer classification (developer, ai-agent, rest-api, kiro-ide).
        allowed_tools: List of tool names this consumer can invoke, or ['*'] for all.
        rate_limit: Maximum calls per rate-limit window for this consumer.
        projects: List of authorized project keys, or ['*'] for all.
        is_active: Whether this consumer is currently enabled.
    """

    api_key: str = ""
    consumer: str = "unknown"
    type: str = "developer"
    allowed_tools: List[str] = field(default_factory=lambda: ["*"])
    rate_limit: int = 15
    projects: List[str] = field(default_factory=lambda: ["*"])
    is_active: bool = True

    def can_access_tool(self, tool_name: str) -> bool:
        """Check if this consumer is authorized to invoke a specific tool.

        Args:
            tool_name: The MCP tool name to check.

        Returns:
            True if authorized (wildcard or exact match).
        """
        if "*" in self.allowed_tools:
            return True
        return tool_name in self.allowed_tools

    def can_access_project(self, project_key: str) -> bool:
        """Check if this consumer is authorized to access a specific project.

        Args:
            project_key: The project key (e.g., 'PROJ').

        Returns:
            True if authorized (wildcard or case-insensitive match).
        """
        if "*" in self.projects:
            return True
        return project_key.upper() in [p.upper() for p in self.projects]


def _load_from_docdb() -> Optional[Dict[str, ConsumerProfile]]:
    """Load consumer registry from DocumentDB.

    Returns:
        Dictionary mapping api_key to ConsumerProfile, or None on failure.
    """
    try:
        from gateway.config.db import get_db
        db = get_db()
        if db is None:
            return None

        registry: Dict[str, ConsumerProfile] = {}
        for doc in db[CONSUMERS_COLLECTION].find({"is_active": {"$ne": False}}):
            api_key = doc.get("api_key", "")
            if api_key:
                registry[api_key] = ConsumerProfile(
                    api_key=api_key,
                    consumer=doc.get("consumer", "unknown"),
                    type=doc.get("type", "developer"),
                    allowed_tools=doc.get("allowed_tools", ["*"]),
                    rate_limit=doc.get("rate_limit", 15),
                    projects=doc.get("projects", ["*"]),
                    is_active=doc.get("is_active", True),
                )
        logger.info("[REGISTRY] Loaded %d consumers from DocumentDB", len(registry))
        return registry
    except Exception as exc:
        logger.warning("[REGISTRY] DocumentDB unavailable: %s", exc)
        return None


def _load_from_file() -> Optional[Dict[str, ConsumerProfile]]:
    """Load consumer registry from a local JSON file (development fallback).

    Returns:
        Dictionary mapping api_key to ConsumerProfile, or None if file missing.
    """
    filepath = os.path.join(os.path.dirname(__file__), "..", "config", "consumers.json")
    if not os.path.exists(filepath):
        return None

    try:
        with open(filepath) as f:
            data = json.load(f)

        registry: Dict[str, ConsumerProfile] = {}
        for entry in data if isinstance(data, list) else data.get("consumers", []):
            api_key = entry.get("api_key", "")
            if api_key:
                registry[api_key] = ConsumerProfile(
                    api_key=api_key,
                    consumer=entry.get("consumer", "unknown"),
                    type=entry.get("type", "developer"),
                    allowed_tools=entry.get("allowed_tools", ["*"]),
                    rate_limit=entry.get("rate_limit", 15),
                    projects=entry.get("projects", ["*"]),
                    is_active=entry.get("is_active", True),
                )
        logger.info("[REGISTRY] Loaded %d consumers from local file", len(registry))
        return registry
    except Exception as exc:
        logger.warning("[REGISTRY] Failed to load local consumer file: %s", exc)
        return None


def _load_consumer_registry() -> Dict[str, ConsumerProfile]:
    """Load the consumer registry with multi-source fallback.

    Priority: DocumentDB -> Local file -> Empty (with warning).

    Returns:
        Dictionary mapping api_key to ConsumerProfile.
    """
    # Tier 1: DocumentDB
    registry = _load_from_docdb()
    if registry is not None:
        return registry

    # Tier 2: Local file
    registry = _load_from_file()
    if registry is not None:
        return registry

    # Tier 3: Empty registry (gateway starts but all API-key auth will fail)
    logger.error("[REGISTRY] No consumer registry available -- all API-key auth will fail")
    return {}


def _ensure_registry_loaded() -> Dict[str, ConsumerProfile]:
    """Return the cached registry, reloading if expired."""
    global _registry_cache, _registry_loaded_at

    now = time.time()
    if _registry_cache and (now - _registry_loaded_at) < _REGISTRY_CACHE_TTL:
        return _registry_cache

    with _registry_lock:
        # Double-check after acquiring lock
        if _registry_cache and (time.time() - _registry_loaded_at) < _REGISTRY_CACHE_TTL:
            return _registry_cache

        _registry_cache = _load_consumer_registry()
        _registry_loaded_at = time.time()
        return _registry_cache


def authenticate(api_key: Optional[str]) -> Optional[ConsumerProfile]:
    """Authenticate a consumer by API key.

    Args:
        api_key: The API key from the X-MCP-API-Key header, or None for stdio.

    Returns:
        ConsumerProfile if authenticated, None if the key is unrecognized.
        None api_key (stdio mode) returns a full-access developer profile.
    """
    if api_key is None:
        # stdio mode: local developer with full access
        return ConsumerProfile(
            api_key="",
            consumer="local",
            type="developer",
            allowed_tools=["*"],
            rate_limit=999,
            projects=["*"],
        )

    registry = _ensure_registry_loaded()
    return registry.get(api_key)


def authorize_tool(consumer: ConsumerProfile, tool_name: str) -> Tuple[bool, str]:
    """Check if a consumer is authorized to invoke a specific tool.

    Args:
        consumer: The authenticated consumer profile.
        tool_name: The MCP tool name.

    Returns:
        Tuple of (allowed: bool, reason: str).
    """
    if consumer.can_access_tool(tool_name):
        return True, "authorized"
    return False, f"Consumer '{consumer.consumer}' is not authorized for tool '{tool_name}'"


def authorize_project(consumer: ConsumerProfile, project_key: str) -> Tuple[bool, str]:
    """Check if a consumer is authorized to access a specific project.

    Args:
        consumer: The authenticated consumer profile.
        project_key: The project key (e.g., 'PROJ').

    Returns:
        Tuple of (allowed: bool, reason: str).
    """
    if consumer.can_access_project(project_key):
        return True, "authorized"
    return False, f"Consumer '{consumer.consumer}' is not authorized for project '{project_key}'"
