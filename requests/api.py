"""Simplified HTTP client used in lieu of the requests dependency."""

from __future__ import annotations

import http.client
import socket
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from .exceptions import ConnectionError, RequestException, Timeout
from .models import Request, Response, _RawHeaders

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _perform_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]],
    body: Optional[bytes],
    timeout: Tuple[float, float],
) -> Tuple[Response, List[Tuple[str, str]], str]:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise RequestException(f"Unsupported URL scheme: {parsed.scheme}")
    host = parsed.hostname
    if not host:
        raise RequestException("URL must include a hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    connect_timeout, read_timeout = timeout

    try:
        if parsed.scheme == "https":
            connection = http.client.HTTPSConnection(
                host, port, timeout=connect_timeout
            )
        else:
            connection = http.client.HTTPConnection(host, port, timeout=connect_timeout)
        connection.connect()
        if connection.sock:
            connection.sock.settimeout(read_timeout)
        request_headers = headers or {}
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        header_pairs = response.getheaders()
        payload = response.read()
    except socket.timeout as exc:
        raise Timeout(str(exc)) from exc
    except OSError as exc:  # pragma: no cover - defensive
        raise ConnectionError(str(exc)) from exc
    finally:
        try:
            connection.close()
        except Exception:  # pragma: no cover - best effort cleanup
            pass

    header_dict = {key: value for key, value in header_pairs}
    raw = type("Raw", (), {"headers": _RawHeaders(header_pairs)})()
    request = Request(method=method, url=url, headers=dict(headers or {}), body=body)
    return (
        Response(
            status_code=response.status,
            url=url,
            headers=header_dict,
            content=payload,
            request=request,
            raw=raw,
        ),
        header_pairs,
        response.headers.get("Location", ""),
    )


def get(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
    timeout: Tuple[float, float] = (5.0, 10.0),
) -> Response:
    body = None
    method = "GET"
    history: List[Response] = []
    current_url = url
    redirects = 0
    while True:
        response, header_pairs, location = _perform_request(
            method, current_url, headers, body, timeout
        )
        response.history = list(history)
        if allow_redirects and response.status_code in _REDIRECT_STATUSES and location:
            history.append(response)
            redirects += 1
            if redirects > 5:
                raise RequestException("Too many redirects")
            current_url = urljoin(current_url, location)
            continue
        return response
