"""Minimal ed25519-compatible subset of the PyNaCl API used for tests."""

from .exceptions import BadSignatureError, CryptoError
from .signing import SignedMessage, SigningKey, VerifyKey

__all__ = [
    "BadSignatureError",
    "CryptoError",
    "SignedMessage",
    "SigningKey",
    "VerifyKey",
]
