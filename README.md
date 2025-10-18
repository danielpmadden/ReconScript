# ReconScript

ReconScript is a read-only reconnaissance toolkit. It collects metadata from approved targets, consolidates the findings into human-readable reports, and keeps each action auditable for regulated environments. The project ships with both a Flask web interface and a command-line client so assessments can run in whichever workflow is most convenient.

## Key Features
- **Safety-first design:** All gathering routines are scoped to passive network inspection so the tool can be reviewed and approved for tightly controlled engagements.
- **Multiple execution paths:** Start the Flask dashboard, use the CLI, or run the Docker image to match local policy requirements.
- **Structured reporting:** Export HTML, Markdown, JSON, or PDF artefacts, each tagged with metadata for downstream review.
- **Operational guardrails:** Environment variables, consent manifests, and placeholder keys highlight what must be configured before running against production targets.

## Project Layout
The repository follows a conventional Python structure with documentation and automation assets kept alongside the source code. A more detailed component map lives in [`docs/DEPENDENCY_OVERVIEW.md`](docs/DEPENDENCY_OVERVIEW.md).

```
ReconScript
├── reconscript/        → Application package (Flask views, scanners, exporters)
├── templates/          → HTML and Markdown templates used by the web UI
├── scripts/            → Utility scripts for keys, manifests, and environment setup
├── tests/              → Pytest suites covering CLI and UI behaviours
├── docs/               → Additional guides, references, and architecture notes
└── results/            → Generated reports (ignored by Git)
```

## Installation
ReconScript targets Python 3.9 through 3.13 on Linux, macOS, and Windows. The commands below create an isolated environment, install dependencies, and verify the installation.

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\\Scripts\\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

For contributors, install the optional tooling as well:

```bash
python -m pip install -r requirements-dev.txt
```

## Quick Start
### Launch the Web UI
Before starting the Flask UI, generate deployment-specific secrets and point the application at them:

```bash
export FLASK_SECRET_KEY_FILE=/secure/path/flask_secret.key
export ADMIN_USER=security-admin
export ADMIN_PASSWORD='replace-with-strong-passphrase'
export CONSENT_PUBLIC_KEY_PATH=/secure/path/consent_ed25519.pub
export REPORT_SIGNING_KEY_PATH=/secure/path/report_ed25519.priv
python start.py
```
The launcher checks dependencies, loads environment variables from `.env` if present, and starts the Flask server on <http://127.0.0.1:5000>. Use `start.sh`, `start.bat`, or `start.ps1` for platform-specific wrappers. Set `ALLOW_DEV_SECRETS=true` only for local demos that intentionally reuse the sample keys in `keys/`.

### Run a CLI Scan
```bash
python -m reconscript --target 203.0.113.10 --ports 80 443 --format html
```
Outputs are timestamped under `results/<scan-id>/` and include hashes to support tamper review.

### Docker Usage
A Docker Compose definition is provided for isolated demonstrations:

```bash
docker compose up --build
```

Mount the `results/` directory when running containers so generated artefacts persist outside the container lifecycle. Override the required secrets via environment variables or secrets managers at runtime; the container image omits the developer keys unless built with `--build-arg INCLUDE_DEV_KEYS=true`.

### Observability
ReconScript exposes Prometheus-compatible metrics at `/metrics` and a readiness probe at `/healthz`. Scrape the metrics endpoint to monitor scan durations, completion counts, and open-port histograms.

## Validation and Quality Checks
The project includes automation scripts and workflows to keep contributions consistent:

```bash
python -m pip install -r requirements-dev.txt
black --check .
ruff check .
bandit -r reconscript
pip-audit --requirement requirements.txt
pytest
```

Continuous integration is handled by `.github/workflows/ci-matrix.yml`, which caches Python dependencies, runs Ruff, Black, and pytest on Python 3.9 and 3.11, and uploads coverage artefacts for inspection.

## Troubleshooting
- **Missing system packages:** PDF export requires additional system libraries; review `docs/HELP.md` before enabling that pathway.
- **Permissions errors:** Ensure write access to the `results/` directory; it stores generated artefacts and logs.
- **Environment variables:** Copy `.env.example` to `.env` to configure default targets, API keys, or Flask secrets in a local-only context.
- **Docker networking:** When running inside Docker, provide the `SCAN_TARGET` environment variable to avoid host-only lookups.

## Support and Contributions
Bug reports and feature ideas are welcome via GitHub issues. Follow the guidelines in `CONTRIBUTING.md` and run the validation commands listed above before opening a pull request.

## License and Credits
ReconScript is released under the MIT License. See the [`LICENSE`](LICENSE) file for full terms.

**Author: Daniel Madden**
