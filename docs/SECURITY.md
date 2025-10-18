# Security Overview — ReconScript

## Purpose
ReconScript is a passive reconnaissance and reporting tool designed for authorized network assessments. It performs safe, read-only analysis of HTTP, TLS, and metadata without exploitation, injection, fuzzing, or privilege escalation.

## Security Posture
- **Non-Destructive:** Performs only TCP connect, HTTP GET, and TLS certificate parsing.
- **Input Validation:** All targets validated and sanitized; no command injection or path traversal possible.
- **Isolation:** Docker image runs as non-root with a read-only filesystem except for /app/results.
- **Sanitized Logging:** Sensitive IPs and hostnames are anonymized when privacy mode is enabled.
- **Safe Defaults:** Scans only explicitly provided targets and ports. No recursive crawling or brute force.
- **Transport Security:** All HTTPS requests use Python’s `ssl.create_default_context()` with modern cipher suites.
- **CSP & Security Headers:** UI protected by Flask-Talisman enforcing:
  - Content-Security-Policy
  - X-Frame-Options
  - Referrer-Policy
  - Permissions-Policy
  - Strict-Transport-Security
- **Error Handling:** No internal tracebacks are exposed to users.
- **Dependency Management:** All Python dependencies pinned and audited using `pip-audit` and `safety`.
- **Static Analysis:** Code scanned regularly with `bandit` and `flake8` to detect security flaws.
- **Reproducible Builds:** Docker and virtual environments ensure consistent behavior across systems.
- **Disclosure Policy:** If a vulnerability is discovered, report it responsibly via GitHub Issues or direct contact with maintainers.

## Out-of-Scope Behavior
- No exploitation, payload delivery, or fuzzing.
- No credential harvesting or token usage.
- No automated network discovery beyond provided targets.

## Author & Contact
Created by Daniel Madden  
GitHub: [danielpmadden](https://github.com/danielpmadden)  
License: MIT  
Version: 0.7.0
