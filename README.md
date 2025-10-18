<p align="center">
  <img src="https://img.shields.io/badge/Language-Python_3.9–3.13-blue?logo=python&logoColor=white" alt="Python 3.9–3.13">
  <img src="https://img.shields.io/badge/Framework-Flask-green?logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/UI-Web_UI-orange?logo=html5&logoColor=white" alt="Web UI">
  <img src="https://img.shields.io/badge/License-MIT-yellow?logo=open-source-initiative&logoColor=white" alt="MIT">
</p>

# ReconScript

*Safe, automated reconnaissance with clean reporting for authorized assessments.*

> ReconScript is a modern, non-destructive reconnaissance and reporting framework built for defenders, red teams on scoped engagements, and compliance-focused assessments. It automates TCP connect discovery, HTTP/TLS metadata collection, robots.txt/header reviews, and compiles professional-grade HTML, Markdown, JSON, or PDF reports—without intrusive exploitation.

---

## Project Overview

- **Automated, safe reconnaissance** covering HTTP, HTTPS, TLS metadata, robots.txt, headers, and more using read-only probes.
- **Multi-format reporting** delivered as HTML dashboards, machine-friendly JSON, clean Markdown, or PDF exports.
- **Flexible deployments** that run locally or in Docker with a polished web interface for managing scans and reports.
- **Ethical-by-design** workflows that reinforce permission-based, legitimate testing practices.

---

## Key Features

- **Safe & Read-Only Scanning:** TCP connect probes with HTTP/TLS inspection—no intrusive exploits or payloads.
- **Web-Based UI:** Launch scans, follow live progress, and open reports directly from your browser.
- **Multiple Output Formats:** Export findings to HTML, JSON, Markdown, or PDF to match stakeholder needs.
- **Cross-Platform:** Works on Windows, macOS, Linux, or packaged Docker containers.
- **One-Click Start:** `start.sh`, `start.bat`, or `docker compose up` bootstraps the full stack instantly.
- **Auto Browser Launch:** Automatically opens the UI once the service is ready.
- **Versioned Reports:** Timestamped report directories saved under `/results` for easy audit trails.
- **Rich Logging:** Colorized terminal output with timestamps for transparent activity tracking.
- **Extensible Design:** Modular architecture poised for plugins, integrations, and advanced automations.

---

## Tech Stack

- **Language:** Python 3.9–3.13
- **Framework:** Flask
- **Frontend:** HTML, CSS, JavaScript
- **Reporting:** WeasyPrint (PDF export)
- **Containerization:** Docker & Docker Compose
- **Formatting / Logging:** Rich, Tabulate, Jinja2

---

## Installation

### Option 1 — Quick Start (One Click)
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/ReconScript.git
cd ReconScript
./start.sh
```
Then open → <http://127.0.0.1:5000>

### Option 2 — Windows
```powershell
git clone https://github.com/YOUR_GITHUB_USERNAME/ReconScript.git
cd ReconScript
start.bat
```

### Option 3 — Docker
```bash
docker compose up
```
or
```bash
docker build -t reconscript .
docker run --rm -p 5000:5000 -v ${PWD}/results:/app/results reconscript
```

---

## Usage

### From the Web UI
1. Enter the authorized target IP or hostname.
2. *(Optional)* Specify ports (default: 80, 443, 8080, 8443, 8000, 3000).
3. Choose the desired output format.
4. Click **Run Scan** and follow live progress updates.
5. Retrieve reports from the **Reports** tab or from the `/results` directory.

### From the Command Line
```bash
python -m reconscript --target 127.0.0.1 --ports 80 443 8080 --format html
```

---

## Architecture Overview

- `core.py`: TCP and HTTP reconnaissance engine.
- `scanner.py`: Probe orchestration with retries and throttling.
- `report.py`: Structured report assembly for HTML, JSON, Markdown, and PDF.
- `ui.py`: Flask-driven web interface and REST endpoints.
- `templates/`: Jinja2 templates backing dashboards and reports.
- `static/`: JavaScript, CSS, and supporting assets.
- `start.py`: Smart launcher detecting local, Docker, or WSL environments.
- `install_dependencies.py`: Dependency bootstrapper.

```
 ┌──────────────────────┐
 │  Web UI (Flask)      │
 │   └── UI routes      │
 ├──────────────────────┤
 │  Recon Engine        │
 │   ├── TCP scanner    │
 │   ├── HTTP analyzer  │
 │   └── Report builder │
 ├──────────────────────┤
 │  Output Formats      │
 │   ├── HTML / JSON    │
 │   ├── Markdown / PDF │
 └──────────────────────┘
```

---

## Example Output

```text
Scan Summary
PORT | SERVICE  | STATUS | NOTES
-----+----------+--------+------------------------------
80   | HTTP     | open   | missing security headers
443  | HTTPS    | open   | TLS certificate valid
8080 | HTTP-alt | closed | filtered or no response
```

---

## Example Targets (Safe)

Use only approved or demonstration systems:

- <https://scanme.nmap.org>
- <https://example.com>
- Local lab environments (e.g., `127.0.0.1`, Docker containers)

---

## Advanced Configuration

`.env` overrides core defaults:
```ini
DEFAULT_PORT=5000
RESULTS_DIR=results
ENABLE_IPV6=true
```

- `install_dependencies.py` ensures required libraries are present.
- `requirements.txt` and `pyproject.toml` define deterministic dependency sets.

---

## License & Legal Disclaimer

- Licensed under the **MIT License**.
- Designed strictly for **authorized, ethical security testing**.
- **Do not** scan systems without explicit written permission from the owner.

---

## Contributing

We welcome ideas, bug reports, and pull requests:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing-improvement`).
3. Follow PEP 8 formatting, use Black for formatting, and ensure unit tests (`pytest`) pass.
4. Open a pull request describing your changes and validation.

Continuous Integration is configured to lint, test, and validate builds automatically.

---

## Roadmap

- Shodan / Censys enrichment integrations.
- Background scan queue for scheduled assessments.
- Remote API mode for automation pipelines.
- Authentication and RBAC for shared web UIs.

---

## Credit

- **Author:** Daniel Madden
- **Frameworks:** Flask, Rich, WeasyPrint
- **Inspiration:** OWASP Juice Shop, Nmap, RapidRecon

---

ReconScript keeps reconnaissance ethical, auditable, and production-ready—empowering defenders with the context they need without crossing the line.

---

## Security controls & consent workflow

ReconScript enforces scope validation and explicit consent:

- Targets must be single IPv4/IPv6 addresses or hostnames. CIDR notation is rejected unless `ALLOW_CIDR=true` and the range collapses to a single host.
- Non-local targets (`127.0.0.1`/`localhost`/`::1` excluded) require a signed manifest that includes `owner_name`, `owner_email`, `target`, permitted ports, validity window, and an ed25519 signature.
- Evidence levels:
  - `low` (default) – sanitized metadata only.
  - `medium` – headers plus artefact placeholders.
  - `high` – full request/response logs; only permitted with manifests explicitly authorising `"evidence_level": "high"`.
- Reports include a SHA256 `report_hash`, optional signature, and are indexed in `results/index.json` for auditability.

Generate a development manifest using:
```bash
python scripts/generate_scope_manifest.py \
  --owner-name "Example Corp" \
  --owner-email "security@example.com" \
  --target 127.0.0.1 \
  --ports 80 443 \
  --output dev-manifest.json
```

## Environment quick references

| Variable | Default | Purpose |
| --- | --- | --- |
| `ENABLE_PUBLIC_UI` | `false` | Bind UI to `0.0.0.0` when `true` (requires `ENABLE_RBAC=true`). |
| `ENABLE_RBAC` | `false` | Enable Flask-Login admin guard. |
| `ADMIN_USER` / `ADMIN_PASSWORD` | `admin` / `changeme` | Development credentials (replace in production). |
| `CONSENT_PUBLIC_KEY_PATH` | `keys/dev_ed25519.pub` | Consent signature verification key. |
| `REPORT_SIGNING_KEY_PATH` | `keys/dev_ed25519.priv` | Private key used when `--sign-report` is supplied. |
| `FLASK_SECRET_KEY_FILE` | `keys/dev_flask_secret.key` | Secret key for Flask sessions. |
| `TOKEN_RATE` / `TOKEN_CAPACITY` | `5` / `10` | Token bucket rate limiting TCP probes. |
| `HTTP_WORKERS` | `2` | Concurrent HTTP workers. |

The `keys/` directory ships with **development-only** keys. Replace them before any production deployment.

## Testing

Run deterministic unit tests:
```bash
pytest -m "not integration"
```

Opt-in integration tests:
```bash
INTEGRATION=true INTEGRATION_SCANME=true pytest -m integration
```

## Running the CLI safely

Example local scan with JSON output and signed report:
```bash
python -m reconscript --target 127.0.0.1 --format json --sign-report
```

Reports are stored under `results/<report_id>/` along with consent manifests and optional signatures.
