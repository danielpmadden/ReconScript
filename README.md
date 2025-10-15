# ReconScript

ReconScript is a defensive reconnaissance assistant designed for authorised web
application assessments. It performs a concise series of **read-only checks** to
catalogue exposed services, review HTTP security posture, and capture
supporting evidence in a single JSON report.

> ⚠️ ReconScript is expressly intended for ethical security reviews conducted
> with explicit permission. Always confirm scope and comply with applicable
> laws, engagement rules, and rate limits.

## Features
- **TCP connect scan** of a configurable, engagement-friendly port list.
- **HTTP(S) metadata collection** including response codes, headers, and a brief
  body snippet for analyst context.
- **Security header review** highlighting recommended controls that are present
  or missing.
- **Cookie flag inspection** using robust parsing for the Secure and HttpOnly
  attributes.
- **TLS certificate snapshot** (when HTTPS is exposed) capturing issuer, subject
  and validity information.
- **robots.txt retrieval** to surface crawler directives that may hint at hidden
  content.
- **Automatic findings** summarising missing controls, cookie risks, and server
  errors.

## Installation
ReconScript targets Python 3.9 or later.

```bash
python -m venv .venv
source .venv/bin/activate
pip install .
```

For development or testing, install pytest as well:

```bash
pip install pytest
```

## Usage
Run the CLI via the console script or Python module entry point:

```bash
safe-recon --target 203.0.113.5 --hostname example.com --outfile recon.json
```

The same invocation is available through `python -m reconscript`.

### Key Options
- `--target` *(required)* – IPv4 or IPv6 address that has been approved for the
  assessment. Validation is enforced before any network activity occurs.
- `--hostname` – Host header and TLS SNI value for name-based services.
- `--ports` – Space-separated list of TCP ports to probe. Defaults to common
  web stack ports (80, 443, 8080, 8443, 8000, 3000).
- `--outfile` – Write the JSON report to a file instead of standard output.
- `--socket-timeout` / `--http-timeout` – Tune socket and HTTP timeouts (in
  seconds) to accommodate slower networks.
- `--max-retries` / `--backoff` – Configure HTTP retry behaviour with
  exponential backoff for transient issues.
- `--throttle` – Delay between port probes to respect engagement rate limits.
- `--enable-ipv6` – Opt-in IPv6 resolution and scanning.
- `--verbose` / `--quiet` – Adjust logging verbosity using Python's logging
  infrastructure.

### Example Output Schema
The generated JSON aligns with the following structure (full example located at
[`examples/sample_report.json`](examples/sample_report.json)):

```json
{
  "target": "203.0.113.5",
  "hostname": "example.com",
  "ports": [80, 443, 8080],
  "version": "0.2.0",
  "timestamp": "2024-01-01T00:00:00Z",
  "open_ports": [80, 443],
  "http_checks": {
    "80": {
      "url": "http://example.com",
      "status_code": 200,
      "server_headers": {"Content-Type": "text/html"},
      "body_snippet": "<!doctype html>...",
      "cookie_flags": {"secure": false, "httponly": true},
      "security_headers_check": {
        "present": {"Content-Security-Policy": "default-src 'self'"},
        "missing": ["Strict-Transport-Security"]
      }
    }
  },
  "tls_cert": {"subject": {"commonName": "example.com"}},
  "robots": {"note": "robots.txt not present or inaccessible"},
  "findings": [
    {"port": 80, "issue": "missing_security_headers", "details": ["Strict-Transport-Security"]}
  ]
}
```

## Troubleshooting & FAQ
**Why does the scan fail immediately?**
: Ensure the `--target` value is an IP address. Hostnames are intentionally
  rejected to avoid unscoped traffic; combine `--target` with `--hostname` when
  SNI is required.

**Can I disable IPv6?**
: IPv6 scanning is disabled by default. Pass `--enable-ipv6` only when scope
  covers the address space.

**What if robots.txt retrieval logs warnings?**
: Intermittent HTTPS issues are handled via retries and logged at debug level
  unless `--verbose` is specified. These warnings are informational and the tool
  continues to the next step.

**How can I respect strict rate limits?**
: Increase `--throttle` (e.g. `--throttle 1.0`) to insert a one-second pause
  between each TCP connection attempt.

## Ethical Operation
ReconScript never attempts authentication, credential guessing, fuzzing, or
service disruption. Nevertheless, you must:

1. Obtain written authorisation for every environment you inspect.
2. Honour organisational rate limits and maintenance windows.
3. Store collected data securely and delete it once no longer required.
4. Report discovered issues responsibly to the system owner.

By running ReconScript you confirm that you understand and will abide by these
principles.
