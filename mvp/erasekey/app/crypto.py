from __future__ import annotations

import json
import os
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .utils import canonical_json

class CryptoError(Exception):
    """Raised when cryptographic operations fail at the record level."""

def encrypt_payload(data_key: bytes, payload: Dict[str, Any], aad: Dict[str, Any]) -> Tuple[bytes, bytes]:
    """Encrypts a JSON payload using AES-256-GCM. Returns (ciphertext, nonce)."""
    if len(data_key) != 32:
        raise CryptoError("Data key must be 32 bytes for AES-256-GCM.")
    nonce = os.urandom(12)
    aes = AESGCM(data_key)
    plaintext = canonical_json(payload).encode('utf-8')
    aad_bytes = canonical_json(aad).encode('utf-8')
    ciphertext = aes.encrypt(nonce, plaintext, aad_bytes)
    return ciphertext, nonce

def decrypt_payload(data_key: bytes, ciphertext: bytes, nonce: bytes, aad: Dict[str, Any]) -> Dict[str, Any]:
    """Decrypts a JSON payload using AES-256-GCM."""
    if len(data_key) != 32:
        raise CryptoError("Data key must be 32 bytes for AES-256-GCM.")
    aes = AESGCM(data_key)
    aad_bytes = canonical_json(aad).encode('utf-8')
    try:
        plaintext = aes.decrypt(nonce, ciphertext, aad_bytes)
    except InvalidTag as exc:
        raise CryptoError("Unable to decrypt record. Integrity check failed.") from exc
    except Exception as exc:
        raise CryptoError("Unable to decrypt record.") from exc

    return json.loads(plaintext.decode('utf-8'))
