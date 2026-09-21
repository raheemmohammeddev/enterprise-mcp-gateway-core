"""
Enterprise MCP Gateway - AES-256-GCM Envelope Encryption (AWS KMS).

Implements enterprise-grade token encryption using the envelope pattern:

    1. KMS generates a Data Encryption Key (DEK) per operation
    2. DEK encrypts the plaintext token with AES-256-GCM
    3. KMS encrypts the DEK with the Customer Master Key (CMK)
    4. Stored: encrypted_token + encrypted_DEK + nonce (no plaintext anywhere)

To decrypt:
    1. Send encrypted_DEK to KMS -> get plaintext DEK
    2. Use DEK to decrypt the token via AES-256-GCM

Benefits:
    - Tokens encrypted at rest in DocumentDB
    - Master key never leaves KMS (HSM-backed)
    - CloudTrail logs every decrypt operation
    - Key rotation via KMS without re-encrypting data
    - Fernet fallback for local development when KMS is unavailable
"""

from __future__ import annotations

import base64
import logging
import os
from typing import Any, Dict, Optional

from gateway.config.settings import AWS_REGION, ENCRYPTION_ENABLED, KMS_KEY_ID

logger = logging.getLogger("enterprise-mcp-gateway.encryption")

# Fallback symmetric key for local dev (NOT used in production)
_LOCAL_FERNET_KEY: str = os.getenv("LOCAL_ENCRYPTION_KEY", "")


def encrypt_token(plaintext: str) -> Dict[str, Any]:
    """Encrypt a token using AWS KMS envelope encryption.

    Attempts KMS first, falls back to Fernet, then stores plaintext
    as a last resort (with a loud warning).

    Args:
        plaintext: The secret to encrypt (PAT, API key, etc.).

    Returns:
        Dict suitable for DocumentDB storage:
        {
            "ciphertext": base64-encoded encrypted token,
            "encrypted_key": base64-encoded encrypted DEK (KMS only),
            "nonce": base64-encoded nonce/IV (KMS only),
            "method": "kms-aes256gcm" | "fernet" | "none"
        }
    """
    if not ENCRYPTION_ENABLED or not plaintext:
        return {"ciphertext": plaintext, "method": "none"}

    # Try KMS envelope encryption
    try:
        return _encrypt_with_kms(plaintext)
    except Exception as exc:
        logger.warning("[ENCRYPTION] KMS unavailable, trying Fernet fallback: %s", exc)

    # Fallback to Fernet (local dev)
    try:
        return _encrypt_with_fernet(plaintext)
    except Exception as exc:
        logger.warning("[ENCRYPTION] Fernet unavailable: %s", exc)

    # Last resort: plaintext (should never happen in production)
    logger.error("[ENCRYPTION] NO ENCRYPTION AVAILABLE -- storing token in plaintext!")
    return {"ciphertext": plaintext, "method": "none"}


def decrypt_token(encrypted_data: Dict[str, Any]) -> Optional[str]:
    """Decrypt a token from its stored encrypted form.

    Args:
        encrypted_data: Dict with ciphertext, encrypted_key, nonce, method.

    Returns:
        Plaintext token string, or None if decryption fails.
    """
    if not encrypted_data:
        return None

    method = encrypted_data.get("method", "none")

    if method == "none":
        return encrypted_data.get("ciphertext")

    if method == "kms-aes256gcm":
        try:
            return _decrypt_with_kms(encrypted_data)
        except Exception as exc:
            logger.error("[ENCRYPTION] KMS decryption failed: %s", exc)
            return None

    if method == "fernet":
        try:
            return _decrypt_with_fernet(encrypted_data)
        except Exception as exc:
            logger.error("[ENCRYPTION] Fernet decryption failed: %s", exc)
            return None

    logger.error("[ENCRYPTION] Unknown encryption method: %s", method)
    return None


# ======================================================================
# KMS Envelope Encryption (Production)
# ======================================================================

def _encrypt_with_kms(plaintext: str) -> Dict[str, Any]:
    """Encrypt using AWS KMS envelope encryption (AES-256-GCM).

    Raises:
        Exception: If KMS or cryptography operations fail.
    """
    import boto3
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    kms_client = _get_kms_client()

    # Generate a data encryption key from KMS
    response = kms_client.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")
    plaintext_key = response["Plaintext"]       # 32 bytes for AES-256
    encrypted_key = response["CiphertextBlob"]  # Encrypted DEK to store

    # Encrypt the token with AES-256-GCM
    aesgcm = AESGCM(plaintext_key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "method": "kms-aes256gcm",
    }


def _decrypt_with_kms(encrypted_data: Dict[str, Any]) -> str:
    """Decrypt using AWS KMS envelope encryption.

    Raises:
        Exception: If KMS or cryptography operations fail.
    """
    import boto3
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    kms_client = _get_kms_client()

    # Decrypt the DEK using KMS
    encrypted_key = base64.b64decode(encrypted_data["encrypted_key"])
    response = kms_client.decrypt(CiphertextBlob=encrypted_key)
    plaintext_key = response["Plaintext"]

    # Decrypt the token with AES-256-GCM
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    nonce = base64.b64decode(encrypted_data["nonce"])
    aesgcm = AESGCM(plaintext_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext.decode("utf-8")


def _get_kms_client():
    """Create a boto3 KMS client with optional MCP-specific credentials."""
    import boto3

    mcp_access_key = os.getenv("MCP_AWS_ACCESS_KEY_ID", "")
    mcp_secret_key = os.getenv("MCP_AWS_SECRET_ACCESS_KEY", "")
    if mcp_access_key and mcp_secret_key:
        return boto3.client(
            "kms",
            region_name=AWS_REGION,
            aws_access_key_id=mcp_access_key,
            aws_secret_access_key=mcp_secret_key,
        )
    return boto3.client("kms", region_name=AWS_REGION)


# ======================================================================
# Fernet Fallback (Local Development Only)
# ======================================================================

def _encrypt_with_fernet(plaintext: str) -> Dict[str, Any]:
    """Fallback: Fernet symmetric encryption (local dev only)."""
    from cryptography.fernet import Fernet

    key = _LOCAL_FERNET_KEY or Fernet.generate_key().decode()
    if not _LOCAL_FERNET_KEY:
        logger.warning("[ENCRYPTION] Auto-generated Fernet key (won't survive restart)")

    f = Fernet(key.encode() if isinstance(key, str) else key)
    ciphertext = f.encrypt(plaintext.encode("utf-8"))

    return {"ciphertext": ciphertext.decode(), "method": "fernet"}


def _decrypt_with_fernet(encrypted_data: Dict[str, Any]) -> str:
    """Fallback: Fernet decryption."""
    from cryptography.fernet import Fernet

    key = _LOCAL_FERNET_KEY
    if not key:
        raise ValueError("LOCAL_ENCRYPTION_KEY not set -- cannot decrypt Fernet tokens")

    f = Fernet(key.encode() if isinstance(key, str) else key)
    plaintext = f.decrypt(encrypted_data["ciphertext"].encode())
    return plaintext.decode("utf-8")
