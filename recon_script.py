#!/usr/bin/env python3
"""Safe reconnaissance script for scoped web-application review.

This module implements non-destructive checks intended for defensive
security assessments. Only TCP connect calls, HTTP(S) GET requests,
certificate inspection, and robots.txt retrieval are performed, keeping the
operation within a read-only scope.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import socket
import ssl
from typing import Dict, Iterable, List, Optional

import requests

# common ports to check (add/remove per scope)
COMMON_PORTS = [80, 443, 8080, 8443, 8000, 3000]

# basic mapping of port -> service guesses
PORT_GUESS = {80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt", 8000: "http-alt", 3000: "http-dev"}

# timeouts
SOCKET_TIMEOUT = 3
HTTP_TIMEOUT = 8

LOGGER = logging.getLogger(__name__)


def tcp_connect_scan(target_ip: str, ports: Iterable[int] = COMMON_PORTS) -> List[int]:
    """Perform a TCP connect scan for the provided ports.

    Parameters
    ----------
    target_ip:
        The IPv4 or IPv6 address to probe.
    ports:
        An iterable of integer port numbers to attempt connections to.

    Returns
    -------
    list[int]
        Ports where a TCP connection was successfully established.
    """

    open_ports: List[int] = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Short timeouts ensure we do not hang on unresponsive hosts, keeping the scan polite.
        sock.settimeout(SOCKET_TIMEOUT)
        try:
            sock.connect((target_ip, port))
            open_ports.append(port)
        except Exception:
            # Silence expected connection failures while keeping the scan non-intrusive.
            continue
        finally:
            sock.close()
    return open_ports


def get_http_info(host_or_ip: str, port: int) -> Dict[str, object]:
    """Collect HTTP response details for a given host and port.

    Parameters
    ----------
    host_or_ip:
        Hostname or IP used to construct the request URL.
    port:
        The destination TCP port that serves HTTP(S).

    Returns
    -------
    dict
        Dictionary containing response metadata or an error message.
    """

    scheme = "https" if port in (443, 8443) else "http"
    if host_or_ip.startswith("http"):
        base = host_or_ip
    else:
        base = (
            f"{scheme}://{host_or_ip}:{port}"
            if port not in (80, 443)
            else f"{scheme}://{host_or_ip}"
        )

    try:
        response = requests.get(
            base,
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "ReconBOT/1.0"},
        )
    except requests.exceptions.SSLError as error:
        return {"error": f"SSL error: {error}"}
    except Exception as error:
        return {"error": str(error)}

    info: Dict[str, object] = {
        "url": response.url,
        "status_code": response.status_code,
        "server_headers": dict(response.headers),
        # Capture a small portion of the body for context without storing large data.
        "body_snippet": response.text[:2000].replace("\n", " "),
    }

    # Cookies: inspect Set-Cookie headers for security attributes without modifying them.
    set_cookie_headers = response.headers.get("Set-Cookie")
    if set_cookie_headers:
        info["set_cookie_raw"] = set_cookie_headers
        flags: Dict[str, bool] = {}
        for part in set_cookie_headers.split(","):
            lowered_part = part.lower()
            flags["secure"] = flags.get("secure", False) or ("secure" in lowered_part)
            flags["httponly"] = flags.get("httponly", False) or ("httponly" in lowered_part)
        info["cookie_flags"] = flags

    return info


def check_security_headers(headers: Dict[str, str]) -> Dict[str, object]:
    """Evaluate standard security headers in an HTTP response.

    Parameters
    ----------
    headers:
        Case-preserving dictionary of response headers.

    Returns
    -------
    dict
        Mapping of present headers and a list of recommended headers that are missing.
    """

    recommended = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "X-Frame-Options",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "X-XSS-Protection": "X-XSS-Protection",
        "Set-Cookie": "Cookies (Secure/HttpOnly)",
    }
    result = {"present": {}, "missing": []}
    for key in recommended:
        if any(header.lower() == key.lower() for header in headers.keys()):
            result["present"][key] = headers.get(key)
        else:
            result["missing"].append(key)
    return result


def get_cert_info(target_ip: str, port: int = 443, hostname: Optional[str] = None) -> Dict[str, object]:
    """Retrieve TLS certificate metadata for the provided endpoint.

    Parameters
    ----------
    target_ip:
        IP address where the TLS service is exposed.
    port:
        TCP port for the TLS service; defaults to 443.
    hostname:
        Optional hostname to present via SNI for virtual hosting.

    Returns
    -------
    dict
        Certificate metadata or an error message if retrieval fails.
    """

    try:
        context = ssl.create_default_context()
        # Using a context and SNI maintains compatibility while avoiding deprecated APIs.
        with socket.create_connection((target_ip, port), timeout=SOCKET_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname or target_ip) as secure_sock:
                certificate = secure_sock.getpeercert()
                return {
                    "subject": dict(entry[0] for entry in certificate.get("subject", [])),
                    "issuer": dict(entry[0] for entry in certificate.get("issuer", [])),
                    "notBefore": certificate.get("notBefore"),
                    "notAfter": certificate.get("notAfter"),
                    "serialNumber": certificate.get("serialNumber"),
                }
    except Exception as error:
        return {"error": str(error)}


def fetch_robots(host_or_ip: str) -> Dict[str, object]:
    """Fetch the robots.txt file, preferring HTTPS when available.

    Parameters
    ----------
    host_or_ip:
        Hostname or IP where robots.txt should be requested.

    Returns
    -------
    dict
        Details about the robots.txt retrieval or a note if unavailable.
    """

    for scheme in ("https", "http"):
        url = f"{scheme}://{host_or_ip}/robots.txt"
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT)
            # Only return content when the file exists and includes readable data.
            if response.status_code == 200 and response.text.strip():
                return {"url": url, "body": response.text[:2000]}
        except Exception:
            # Ignore failures and fall back to the next scheme to stay non-invasive.
            continue
    return {"note": "no robots.txt found or inaccessible"}


def generate_findings(http_results: Dict[int, Dict[str, object]]) -> List[Dict[str, object]]:
    """Create a summarized list of noteworthy HTTP findings.

    Parameters
    ----------
    http_results:
        Mapping of port numbers to HTTP metadata dictionaries.

    Returns
    -------
    list[dict]
        Summaries of potential security issues derived from HTTP results.
    """

    findings: List[Dict[str, object]] = []
    for port, result in http_results.items():
        if not isinstance(result, dict):
            continue

        missing_headers = result.get("security_headers_check", {}).get("missing", [])
        if missing_headers:
            findings.append(
                {
                    "port": port,
                    "issue": "missing_security_headers",
                    "details": missing_headers,
                }
            )

        cookie_flags = result.get("cookie_flags")
        if cookie_flags and (
            not cookie_flags.get("secure") or not cookie_flags.get("httponly")
        ):
            findings.append(
                {
                    "port": port,
                    "issue": "session_cookie_flags",
                    "details": cookie_flags,
                }
            )

        status_code = result.get("status_code")
        if isinstance(status_code, int) and status_code >= 500:
            findings.append(
                {"port": port, "issue": "server_error", "details": status_code}
            )

    return findings


def main(args: argparse.Namespace) -> Dict[str, object]:
    """Execute the reconnaissance workflow and return structured results.

    Parameters
    ----------
    args:
        Parsed command-line arguments containing target configuration.

    Returns
    -------
    dict
        Complete JSON-serialisable results for the assessment.
    """

    target = args.target
    hostname = args.hostname
    output: Dict[str, object] = {
        "target": target,
        "hostname": hostname,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }

    LOGGER.info("Scanning %s (presented hostname: %s)", target, hostname)

    LOGGER.info("Running TCP connect scan on requested ports")
    open_ports = tcp_connect_scan(target, ports=args.ports)
    output["open_ports"] = open_ports
    LOGGER.info("Open ports detected: %s", open_ports)

    http_results: Dict[int, Dict[str, object]] = {}
    for port in open_ports:
        if port in (80, 443, 8080, 8443, 8000, 3000):
            LOGGER.info("Probing HTTP(S) on port %s", port)
            http_results[port] = get_http_info(hostname or target, port)
            if isinstance(http_results[port], dict) and "server_headers" in http_results[port]:
                security_headers = check_security_headers(http_results[port]["server_headers"])
                http_results[port]["security_headers_check"] = security_headers
    output["http_checks"] = http_results

    if 443 in open_ports or 8443 in open_ports:
        tls_port = 443 if 443 in open_ports else 8443
        LOGGER.info("Fetching TLS certificate information on port %s", tls_port)
        output["tls_cert"] = get_cert_info(target, port=tls_port, hostname=hostname)

    output["robots"] = fetch_robots(hostname or target)

    output["findings"] = generate_findings(http_results)

    if args.outfile:
        with open(args.outfile, "w", encoding="utf-8") as output_file:
            json.dump(output, output_file, indent=2)
        LOGGER.info("Results written to %s", args.outfile)
    else:
        print(json.dumps(output, indent=2))

    return output


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments for the reconnaissance script.

    Parameters
    ----------
    argv:
        Optional iterable of argument strings to parse. Defaults to ``None`` to
        use ``sys.argv`` as provided by ``argparse``.

    Returns
    -------
    argparse.Namespace
        Parsed arguments containing target details and configuration.
    """

    parser = argparse.ArgumentParser(
        description="Safe reconnaissance for in-scope host",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--target",
        required=True,
        help="IP address to scan (required by scope)",
    )
    parser.add_argument(
        "--hostname",
        required=False,
        help="Optional hostname for HTTP/S SNI",
    )
    parser.add_argument(
        "--outfile",
        help="Filename to write JSON results",
    )
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=COMMON_PORTS,
        help="Ports to scan",
    )
    return parser.parse_args(args=argv)


def configure_logging(level: int = logging.INFO) -> None:
    """Configure structured logging for the script.

    Parameters
    ----------
    level:
        Logging level to use for the root logger; defaults to ``INFO``.

    Returns
    -------
    None
    """

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(name)s [%(levelname)s] %(message)s",
    )


if __name__ == "__main__":
    configure_logging()
    CLI_ARGS = parse_args()
    main(CLI_ARGS)
