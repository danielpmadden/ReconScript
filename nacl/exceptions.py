"""Subset of PyNaCl exceptions used within the project."""

class CryptoError(Exception):
    """Base class for signing/verification errors."""


class BadSignatureError(CryptoError):
    """Raised when a signature fails to validate."""
