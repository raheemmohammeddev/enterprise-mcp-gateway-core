"""
Enterprise MCP Gateway - Token Encryption Tests.

Pins the fail-closed behavior of encrypt_token(): with encryption enabled and
no working backend it raises EncryptionUnavailableError instead of returning
the token in plaintext, and the error carries no token material. Also covers
the Fernet round trip and the record_id (AES-GCM associated data) binding.

Synchronous by design (pytest-asyncio is not installed).
"""

import pytest
from cryptography.fernet import Fernet

import gateway.security.kms_envelope as kms
from gateway.security.kms_envelope import (
    EncryptionUnavailableError,
    decrypt_token,
    encrypt_token,
)

_SECRET = "supersecret-token-value"


class TestFailClosed:
    def test_raises_when_no_backend_available(self, monkeypatch):
        monkeypatch.setattr(kms, "ENCRYPTION_ENABLED", True)
        monkeypatch.setattr(
            kms, "_encrypt_with_kms",
            lambda plaintext, record_id="": (_ for _ in ()).throw(RuntimeError("no kms")),
        )
        monkeypatch.setattr(
            kms, "_encrypt_with_fernet",
            lambda plaintext, record_id="": (_ for _ in ()).throw(RuntimeError("no fernet")),
        )

        with pytest.raises(EncryptionUnavailableError) as excinfo:
            encrypt_token(_SECRET)

        assert "supersecret" not in str(excinfo.value)

    def test_disabled_encryption_is_an_explicit_opt_out(self, monkeypatch):
        monkeypatch.setattr(kms, "ENCRYPTION_ENABLED", False)
        result = encrypt_token(_SECRET)
        assert result["method"] == "none"


class TestFernetFallback:
    def test_round_trip(self, monkeypatch):
        monkeypatch.setattr(kms, "ENCRYPTION_ENABLED", True)
        monkeypatch.setattr(kms, "_LOCAL_FERNET_KEY", Fernet.generate_key().decode())
        monkeypatch.setattr(
            kms, "_encrypt_with_kms",
            lambda plaintext, record_id="": (_ for _ in ()).throw(RuntimeError("no kms")),
        )

        encrypted = encrypt_token("abc")
        assert encrypted["method"] == "fernet"
        assert encrypted["ciphertext"] != "abc"
        assert decrypt_token(encrypted) == "abc"

    def test_record_id_binding_is_not_silently_dropped(self, monkeypatch):
        monkeypatch.setattr(kms, "ENCRYPTION_ENABLED", True)
        monkeypatch.setattr(kms, "_LOCAL_FERNET_KEY", Fernet.generate_key().decode())
        monkeypatch.setattr(
            kms, "_encrypt_with_kms",
            lambda plaintext, record_id="": (_ for _ in ()).throw(RuntimeError("no kms")),
        )

        with pytest.raises(EncryptionUnavailableError):
            encrypt_token("abc", record_id="consumer-42")
