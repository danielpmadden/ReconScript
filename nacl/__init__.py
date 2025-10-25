"""Minimal ed25519-compatible subset of the PyNaCl API used for tests."""

# Expose the ``exceptions`` module at the package level to match the
# ``pynacl`` import style used by the application code (``from nacl import
# exceptions``).  Our lightweight shim previously only re-exported the
# classes, which meant importing the module itself failed with
# ``ImportError`` when the real dependency was not installed.
from . import exceptions as exceptions  # noqa: E402  (re-export for compatibility)
from .exceptions import BadSignatureError, CryptoError
from .signing import SignedMessage, SigningKey, VerifyKey

__all__ = [
    "BadSignatureError",
    "CryptoError",
    "SignedMessage",
    "SigningKey",
    "VerifyKey",
    "exceptions",
]
