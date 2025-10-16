# ReconScript

ReconScript is a defensive reconnaissance assistant designed for authorised web
application assessments. It performs a concise series of **read-only checks** to
catalogue exposed services, review HTTP security posture, and capture
supporting evidence in a single JSON report.

> ⚠️ ReconScript is expressly intended for ethical security reviews conducted
> with explicit permission. Always confirm scope and comply with applicable
> laws, engagement rules, and rate limits before running the tool.

## Features
- **TCP connect scan** of a configurable, engagement-friendly port list.
- **HTTP(S) metadata collection** including status codes, headers, body
  snippets, and cookie flag analysis with reliable parsing.
- **Security header review** summarising recommended controls that are present
  or missing.
- **TLS certificate snapshot** (when HTTPS is exposed) capturing issuer, subject
  and validity information.
- **robots.txt retrieval** with retry/backoff behaviour for intermittent
  failures.
- **Automatic findings** highlighting missing headers, insecure cookies, and
  server errors.
- **Safety controls**: target validation, throttling, IPv6 opt-in, dry-run
  preview, configurable timeouts, and capped port lists.

## Installation
ReconScript targets Python 3.9 or later.

```bash
python -m venv .venv
source .venv/bin/activate
pip install .
```

For development or testing, install the optional tooling extras:

```bash
pip install .[dev]
```

## Usage
Run the CLI via the console script or Python module entry point:

```bash
safe-recon --target 203.0.113.5 --hostname example.com --outfile recon.json
# or
python -m reconscript --target 203.0.113.5
```

### Key Options
- `--target` *(required)* – IPv4 or IPv6 address that has been approved for the
  assessment. Validation is enforced before any network activity occurs.
- `--hostname` – Host header and TLS SNI value for name-based services.
- `--ports` – Space-separated list of TCP ports to probe. Defaults to common web
  stack ports (80, 443, 8080, 8443, 8000, 3000).
- `--max-ports` – Cap the number of ports probed in a single run (default 12) to
  avoid unexpected breadth.
- `--timeout-socket` / `--timeout-http` – Tune socket and HTTP timeouts (in
  seconds) to accommodate slower networks.
- `--max-retries` / `--backoff` – Configure the number of HTTP/TLS retry
  attempts (up to three) and exponential backoff delay.
- `--throttle-ms` – Delay in milliseconds between TCP probes; defaults to
  250&nbsp;ms to encourage considerate pacing.
- `--enable-ipv6` – Opt-in IPv6 resolution and scanning when explicitly scoped.
- `--outfile` – Write the JSON report to a file atomically; otherwise results
  are emitted via structured logging.
- `--dry-run` – Print the planned TCP/HTTP actions and exit without touching the
  network.
- `--verbose` / `--quiet` – Adjust logging verbosity using Python’s logging
  infrastructure.

### Dry-run planning
Use `--dry-run` when validating engagement scope or demonstrating behaviour to
stakeholders:

```bash
safe-recon --target 203.0.113.5 --ports 80 443 8080 --dry-run --verbose
```

The command outputs the JSON plan describing the intended probes without opening
any sockets.

## Running in Docker
ReconScript ships with a multi-stage Dockerfile for reproducible, sandboxed
execution. The container image runs as an unprivileged user and exposes only
outbound network activity.

```bash
# build
docker build -t reconscript .

# dry-run demo
docker run --rm reconscript --dry-run --target 127.0.0.1 --verbose

# local scan example (safe target)
docker run --rm --network host -v $(pwd)/results:/app/results \
  reconscript --target 127.0.0.1 --ports 3000 --outfile results/juice_findings.json
```

The compose file (`docker-compose.yml`) provides the same defaults with a named
volume for convenience:

```bash
docker compose up --build reconscript
```

## Continuous Integration
Each commit is automatically tested and built via GitHub Actions.
- Lint and tests run under Python 3.11
- Docker image built and validated in dry-run mode
- Optional vulnerability scan via Trivy
- Successful main-branch builds publish to GHCR: `ghcr.io/<your-username>/reconscript:latest`

### Example: testing OWASP Juice Shop in Docker
1. Start Juice Shop locally (requires Docker):
   ```bash
   docker run --rm -p 3000:3000 bkimminich/juice-shop
   ```
2. Run ReconScript against the container’s loopback IP:
   ```bash
   safe-recon \
     --target 127.0.0.1 \
     --hostname localhost \
     --ports 3000 443 \
     --outfile juice-shop-report.json
   ```
3. Review `juice-shop-report.json` or the sample
   [`examples/findings.json`](examples/findings.json) for the expected metadata
   and findings structure.

### Example Output Schema
The generated JSON contains high-level metadata plus the collected evidence. A
truncated example is shown below (full sample available in
[`examples/sample_report.json`](examples/sample_report.json)):

```json
{
  "target": "203.0.113.5",
  "hostname": "example.com",
  "ports": [80, 443],
  "tool_version": "0.3.0",
  "timestamp": "2024-01-01T00:00:00Z",
  "scan_config": {
    "requested_ports": [80, 443, 8080],
    "effective_ports": [80, 443],
    "socket_timeout": 3.0,
    "http_timeout": 8.0,
    "throttle_ms": 250.0,
    "max_ports": 12,
    "enable_ipv6": false,
    "dry_run": false,
    "max_retries": 2,
    "backoff": 0.5
  },
  "open_ports": [80, 443],
  "http_checks": {
    "80": {
      "url": "http://example.com",
      "status_code": 200,
      "server_headers": {"Content-Type": "text/html"},
      "body_snippet": "<!doctype html>…",
      "cookie_flags": {"secure": false, "httponly": true},
      "security_headers_check": {
        "present": {"Content-Security-Policy": "default-src 'self'"},
        "missing": ["Strict-Transport-Security"]
      }
    }
  },
  "tls_cert": {"note": "TLS not in scope"},
  "robots": {"note": "robots.txt not present or inaccessible"},
  "findings": [
    {
      "port": 80,
      "issue": "missing_security_headers",
      "details": ["Strict-Transport-Security"]
    }
  ],
  "runtime": 1.23
}
```

## Safety & Ethics Checklist
ReconScript never attempts authentication, credential guessing, fuzzing, or
service disruption. Nevertheless, you must:

1. Obtain written authorisation for every environment you inspect.
2. Honour organisational rate limits and maintenance windows; raise
   `--throttle-ms` when in doubt.
3. Store collected data securely and delete it once no longer required.
4. Report discovered issues responsibly to the system owner.

By running ReconScript you confirm that you understand and will abide by these
principles.

## Troubleshooting & FAQ
**The scan exits immediately with an error.** Ensure the `--target` value is an
IP address; hostnames are intentionally rejected to avoid unscoped traffic.
Combine `--target` with `--hostname` when SNI is required.

**Can I disable IPv6?** IPv6 scanning is disabled by default. Pass
`--enable-ipv6` only when scope covers the address space.

**What if robots.txt retrieval logs warnings?** Intermittent HTTPS issues are
handled via retries and logged at debug level unless `--verbose` is specified.
These warnings are informational and the tool continues to the next step.

**How can I respect strict rate limits?** Increase `--throttle-ms` (for example
`--throttle-ms 1000`) to insert a one-second pause between each TCP connection
attempt.

## Test Plan
Run the automated tests with `pytest` (responses is installed via the development
extra):

```bash
pytest
```

Quick CLI smoke checks:

```bash
python -m reconscript --help
python -m reconscript --target 203.0.113.5 --ports 80 443 --dry-run --quiet
```

For local integration testing, follow the Juice Shop example above. For public
internet testing, coordinate with the system owner and run in `--dry-run` first
before contacting any production service.
