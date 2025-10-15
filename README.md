# ReconScript

ReconScript is a lightweight, non-destructive reconnaissance helper for reviewing an in-scope web application. It focuses on safe actions like TCP connect scans, HTTP(S) GET requests, TLS certificate inspection, and fetching `robots.txt`, producing a single JSON report you can hand to your engagement notes.

## Features
- **Common port discovery** using TCP connect scans (defaults to 80, 443, 8080, 8443, 8000, and 3000).
- **HTTP(S) probing** that follows redirects, records response metadata, and captures a short body snippet for context.
- **Security header review** highlighting recommended headers that are present or missing.
- **Cookie flag inspection** for Secure and HttpOnly protections when the server sets cookies.
- **TLS certificate grab** (when HTTPS ports are open) with issuer, subject, validity, and serial number details.
- **`robots.txt` fetcher** to capture any crawler directives exposed by the site.

## Requirements
- Python 3.8+
- `requests` Python package

Install the dependency with:

```bash
pip install requests
```

## Usage
From the repository root run:

```bash
python recon_script.py --target <TARGET_IP> [--hostname <HOSTNAME>] [--outfile results.json] [--ports 80 443]
```

**Arguments**
- `--target` (required): IP address approved by your assessment scope.
- `--hostname`: Optional hostname for HTTP requests and TLS SNI (useful when the service expects a virtual host).
- `--outfile`: Write results to the given JSON file instead of standard output.
- `--ports`: Space-separated list of ports to scan. Defaults to a safe, common web-app set.

### Example

```bash
python recon_script.py --target 203.0.113.5 --hostname example.com --outfile recon.json
```

This command scans the default ports on `203.0.113.5`, probes HTTP(S) using `example.com` as the Host/SNI, and writes a structured JSON report to `recon.json`.

## Output
The script prints (or writes) JSON containing:
- `open_ports`: list of responsive ports from the scan scope.
- `http_checks`: per-port HTTP(S) metadata including status code, headers, body snippet, and security header assessment.
- `tls_cert`: certificate details when HTTPS endpoints are available.
- `robots`: outcome of the `robots.txt` retrieval.
- `findings`: automatically collated observations such as missing security headers, insecure cookie flags, or server errors.

## Safety Notes
- Designed for **consent-based** testing only. Always confirm the scope and authorization before running.
- Uses only safe, read-only network interactions and adheres to engagement-friendly defaults.
- Modify the port list or HTTP headers only when the agreed scope permits.
