"""
Enterprise MCP Gateway - DocumentDB Connection.

Provides a cached MongoDB/DocumentDB client and database handle.
Fail-open: returns None if the database is unavailable, allowing
callers to degrade gracefully.
"""

from __future__ import annotations

import logging
from typing import Optional

from gateway.config.settings import (
    DOCDB_DATABASE,
    DOCDB_HOST,
    DOCDB_PASSWORD,
    DOCDB_PORT,
    DOCDB_TLS_ENABLED,
    DOCDB_USERNAME,
)

logger = logging.getLogger("enterprise-mcp-gateway.db")

_db = None
_client = None


def get_db():
    """Get the DocumentDB database handle (cached).

    Returns:
        pymongo Database object, or None if unavailable.
    """
    global _db, _client

    if _db is not None:
        return _db

    try:
        from pymongo import MongoClient

        if DOCDB_USERNAME and DOCDB_PASSWORD:
            uri = (
                f"mongodb://{DOCDB_USERNAME}:{DOCDB_PASSWORD}"
                f"@{DOCDB_HOST}:{DOCDB_PORT}/{DOCDB_DATABASE}"
                f"?authSource=admin"
            )
            if DOCDB_TLS_ENABLED:
                uri += "&tls=true&tlsAllowInvalidCertificates=true"
        else:
            uri = f"mongodb://{DOCDB_HOST}:{DOCDB_PORT}/{DOCDB_DATABASE}"

        _client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        _db = _client[DOCDB_DATABASE]
        # Quick connectivity check
        _client.admin.command("ping")
        logger.info("[DB] Connected to DocumentDB at %s:%s", DOCDB_HOST, DOCDB_PORT)
        return _db
    except Exception as exc:
        logger.warning("[DB] DocumentDB unavailable: %s", exc)
        _db = None
        return None
