from __future__ import annotations

import os
from typing import Any, Dict, Protocol, Tuple

import boto3
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import settings

class KeyProviderError(Exception):
    """Base error for key provider failures."""

class InvalidKmsState(KeyProviderError):
    """Raised when KMS key is disabled, pending deletion, or unresolvable."""

class KeyProvider(Protocol):
    def generate_data_key(self, encryption_context: Dict[str, str]) -> Tuple[bytes, bytes]:
        """Generates a data key. Returns (plaintext, ciphertext)."""
        ...

    def unwrap_data_key(self, ciphertext: bytes, encryption_context: Dict[str, str]) -> bytes:
        """Unwraps a data key. Returns plaintext."""
        ...

    def describe_provider(self) -> Dict[str, str]:
        """Provides metadata about the active provider."""
        ...

class AwsKmsProvider(KeyProvider):
    def __init__(self, key_id: str) -> None:
        if not key_id:
            raise KeyProviderError("AWS KMS Key ID cannot be empty.")
        self.key_id = key_id
        # Rely on standard boto3 credential resolution (Env, ~/.aws/credentials)
        self.session = boto3.Session()
        self.client = self.session.client("kms")

    def generate_data_key(self, encryption_context: Dict[str, str]) -> Tuple[bytes, bytes]:
        try:
            response = self.client.generate_data_key(
                KeyId=self.key_id,
                KeySpec='AES_256',
                EncryptionContext=encryption_context
            )
            return response['Plaintext'], response['CiphertextBlob']
        except Exception as e:
            raise KeyProviderError(f"Failed to generate AWS KMS data key: {e}") from e

    def unwrap_data_key(self, ciphertext: bytes, encryption_context: Dict[str, str]) -> bytes:
        try:
            response = self.client.decrypt(
                CiphertextBlob=ciphertext,
                EncryptionContext=encryption_context
            )
            return response['Plaintext']
        except self.client.exceptions.InvalidCiphertextException as e:
             raise KeyProviderError("Invalid ciphertext or mismatched encryption context.") from e
        except self.client.exceptions.KMSInvalidStateException as e:
             raise InvalidKmsState("AWS KMS key is disabled or pending deletion.") from e
        except Exception as e:
            raise KeyProviderError(f"Failed to unwrap AWS KMS data key: {e}") from e

    def describe_provider(self) -> Dict[str, str]:
        return {"provider": "aws_kms", "key_id": self.key_id}

class MockKmsProvider(KeyProvider):
    """Simulates KMS behavior using local AES-GCM and enforces encryption context."""
    def __init__(self, key_id: str = "mock-key-id") -> None:
        self.key_id = key_id
        self._master_key = b"mock-kms-master-key-000000000000" # 32 bytes mock master
        self._mock_aes = AESGCM(self._master_key)

    def _canonicalize_context(self, context: Dict[str, str]) -> bytes:
        import json
        return json.dumps(context, sort_keys=True).encode("utf-8")

    def generate_data_key(self, encryption_context: Dict[str, str]) -> Tuple[bytes, bytes]:
        plaintext = os.urandom(32)
        # Mock KMS blob: 12 byte nonce + ciphertext + tag
        nonce = os.urandom(12)
        aad = self._canonicalize_context(encryption_context)
        ciphertext = self._mock_aes.encrypt(nonce, plaintext, aad)
        blob = nonce + ciphertext
        return plaintext, blob

    def unwrap_data_key(self, ciphertext: bytes, encryption_context: Dict[str, str]) -> bytes:
        if len(ciphertext) < 12:
             raise KeyProviderError("Invalid mock ciphertext length")
        nonce = ciphertext[:12]
        payload = ciphertext[12:]
        aad = self._canonicalize_context(encryption_context)
        try:
            plaintext = self._mock_aes.decrypt(nonce, payload, aad)
            return plaintext
        except InvalidTag as e:
            raise KeyProviderError("Invalid ciphertext or mismatched encryption context (Mock).") from e
        except Exception as e:
            raise KeyProviderError(f"Failed to unwrap mock data key: {e}") from e

    def describe_provider(self) -> Dict[str, str]:
        return {"provider": "mock_kms", "key_id": self.key_id}

class KeyResolver:
    @classmethod
    def resolve_provider(cls, tenant_kms_key_id: str | None = None) -> KeyProvider:
        """
        Resolves the appropriate KeyProvider.
        Fallback order: tenant > default environment > mock.
        Always respects ERASEKEY_KMS_MODE.
        """
        mode = settings.kms_mode
        key_id = tenant_kms_key_id or settings.aws_kms_key_id or "default-key"
        
        if mode == "mock":
            return MockKmsProvider(key_id=key_id)
        elif mode == "aws":
            return AwsKmsProvider(key_id=key_id)
        else:
            raise KeyProviderError(f"Unknown KMS mode: {mode}")
