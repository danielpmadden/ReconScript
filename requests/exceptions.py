"""Exceptions compatible with a subset of the real requests library."""


class RequestException(Exception):
    """Base networking error."""


class Timeout(RequestException):
    """Timeout communicating with remote server."""


class ConnectionError(RequestException):
    """Connection establishment failure."""
