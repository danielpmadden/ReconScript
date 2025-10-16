"""Minimal subset of the requests API required for tests."""

from .api import get
from .exceptions import ConnectionError, RequestException, Timeout
from . import exceptions
from .models import Request, Response
from . import utils

__all__ = [
    "ConnectionError",
    "Request",
    "exceptions",
    "RequestException",
    "Response",
    "Timeout",
    "get",
    "utils",
]
