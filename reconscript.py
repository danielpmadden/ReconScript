#!/usr/bin/env python3
"""
Safe reconnaissance script for scoped web-app review.
- Non-destructive: only TCP connect, HTTP(S) GETs, cert inspection, robots.txt.
- Usage: python recon_safe.py --target 203.0.113.5 --host example.com
"""

import socket
import argparse
import json
import requests
import ssl
import datetime
from urllib.parse import urljoin

# common ports to check (add/remove per scope)
COMMON_PORTS = [80, 443, 8080, 8443, 8000, 3000]

# basic mapping of port -> service guesses
PORT_GUESS = {80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt", 8000: "http-alt", 3000: "http-dev"}

# timeouts
SOCKET_TIMEOUT = 3
HTTP_TIMEOUT = 8

def tcp_connect_scan(target_ip, ports=COMMON_PORTS):
    open_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        try:
            s.connect((target_ip, p))
            open_ports.append(p)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports

def get_http_info(host_or_ip, port):
    scheme = "https" if port in (443, 8443) else "http"
    if host_or_ip.startswith("http"):
        base = host_or_ip
    else:
        base = f"{scheme}://{host_or_ip}:{port}" if (port not in (80,443)) else f"{scheme}://{host_or_ip}"
    try:
        r = requests.get(base, timeout=HTTP_TIMEOUT, allow_redirects=True, headers={"User-Agent":"ReconBOT/1.0"})
    except requests.exceptions.SSLError as e:
        return {"error": f"SSL error: {e}"}
    except Exception as e:
        return {"error": str(e)}
    info = {
        "url": r.url,
        "status_code": r.status_code,
        "server_headers": dict(r.headers),
        "body_snippet": r.text[:2000].replace("\n"," ")  # first 2k chars
    }
    # cookies -> find Secure/HttpOnly flags in Set-Cookie headers
    set_cookie_headers = r.headers.get("Set-Cookie")
    if set_cookie_headers:
        info["set_cookie_raw"] = set_cookie_headers
        # quick parsing: check flags
        flags = {}
        for part in set_cookie_headers.split(","):
            p = part.lower()
            flags["secure"] = flags.get("secure", False) or ("secure" in p)
            flags["httponly"] = flags.get("httponly", False) or ("httponly" in p)
        info["cookie_flags"] = flags
    return info

def check_security_headers(headers: dict):
    recommended = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "X-Frame-Options",
        "Referrer-Policy": "Referrer-Policy",
        "Permissions-Policy": "Permissions-Policy",
        "X-Content-Type-Options": "X-Content-Type-Options",
        "X-XSS-Protection": "X-XSS-Protection",  # legacy
        "Set-Cookie": "Cookies (Secure/HttpOnly)"
    }
    result = {"present": {}, "missing": []}
    for k in recommended:
        if any(h.lower() == k.lower() for h in headers.keys()):
            result["present"][k] = headers.get(k)
        else:
            result["missing"].append(k)
    return result

def get_cert_info(target_ip, port=443, hostname=None):
    try:
        # prefer hostname SNI if provided
        ctx = ssl.create_default_context()
        with socket.create_connection((target_ip, port), timeout=SOCKET_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname or target_ip) as ssock:
                cert = ssock.getpeercert()
                # get notBefore / notAfter in readable form
                nb = cert.get("notBefore")
                na = cert.get("notAfter")
                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "notBefore": nb,
                    "notAfter": na,
                    "serialNumber": cert.get("serialNumber")
                }
    except Exception as e:
        return {"error": str(e)}

def fetch_robots(host_or_ip):
    for scheme in ("https","http"):
        url = f"{scheme}://{host_or_ip}/robots.txt"
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT)
            if r.status_code == 200 and r.text.strip():
                return {"url": url, "body": r.text[:2000]}
        except Exception:
            pass
    return {"note": "no robots.txt found or inaccessible"}

def main(args):
    target = args.target
    hostname = args.hostname
    out = {"target": target, "hostname": hostname, "timestamp": datetime.datetime.utcnow().isoformat()+"Z"}
    print(f"[+] Scanning {target} (presented hostname: {hostname})")

    # 1) port scan
    print("[+] Running TCP connect scan on common ports...")
    open_ports = tcp_connect_scan(target, ports=args.ports)
    out["open_ports"] = open_ports
    print(f"    open ports: {open_ports}")

    # 2) http checks
    http_results = {}
    for p in open_ports:
        if p in (80, 443, 8080, 8443, 8000, 3000):
            print(f"[+] Probing HTTP(S) on port {p} ...")
            http_results[p] = get_http_info(hostname or target, p)
            if isinstance(http_results[p], dict) and "server_headers" in http_results[p]:
                sec = check_security_headers(http_results[p]["server_headers"])
                http_results[p]["security_headers_check"] = sec
    out["http_checks"] = http_results

    # 3) TLS cert if 443 open
    if 443 in open_ports or 8443 in open_ports:
        p = 443 if 443 in open_ports else 8443
        print(f"[+] Fetching TLS cert info on port {p} ...")
        out["tls_cert"] = get_cert_info(target, port=p, hostname=hostname)

    # 4) robots.txt
    out["robots"] = fetch_robots(hostname or target)

    # 5) simple findings extract
    findings = []
    for p,r in http_results.items():
        if isinstance(r, dict):
            miss = r.get("security_headers_check", {}).get("missing", [])
            if miss:
                findings.append({
                    "port": p,
                    "issue": "missing_security_headers",
                    "details": miss
                })
            if r.get("cookie_flags") and (not r["cookie_flags"].get("secure") or not r["cookie_flags"].get("httponly")):
                findings.append({
                    "port": p,
                    "issue": "session_cookie_flags",
                    "details": r.get("cookie_flags")
                })
            if isinstance(r.get("status_code"), int) and r["status_code"] >= 500:
                findings.append({"port": p, "issue": "server_error", "details": r["status_code"]})
    out["findings"] = findings

    # 6) output
    if args.outfile:
        with open(args.outfile, "w") as f:
            json.dump(out, f, indent=2)
        print(f"[+] Results written to {args.outfile}")
    else:
        print(json.dumps(out, indent=2))

def build_arg_parser():
    parser = argparse.ArgumentParser(description="Safe reconnaissance for in-scope host")
    parser.add_argument("--target", required=True, help="IP address to scan (required by scope)")
    parser.add_argument("--hostname", required=False, help="optional hostname for HTTP/S SNI")
    parser.add_argument("--outfile", help="filename to write JSON results")
    parser.add_argument("--ports", nargs="+", type=int, default=COMMON_PORTS, help="ports to scan")
    return parser


def cli(argv=None):
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    main(args)


if __name__ == "__main__":
    cli()
