# Dependency Overview

ReconScript is organised around a central application package with supporting interfaces and helper utilities. The diagram below summarises the major modules and how they relate to each other.

```
ReconScript
├── reconscript/
│   ├── cli.py             → Command-line entry point coordinating scans and report generation
│   ├── ui.py              → Flask routes, session handling, and template rendering
│   ├── core.py            → High-level orchestration for scan execution
│   ├── scanner/           → Passive network probes and metadata collectors
│   ├── reporters.py       → Builders for HTML, Markdown, JSON, and PDF outputs
│   ├── report.py          → Report assembly helpers shared by exporters and UI
│   ├── consent.py         → Consent manifest parsing and validation utilities
│   └── templates/         → Embedded HTML fragments consumed by the Flask interface
├── recon_script.py        → Legacy convenience launcher retained for backward compatibility
├── start.py / start.sh    → Environment detection and bootstrap scripts for local usage
├── templates/             → HTML and Markdown templates used by Flask and the reporting pipeline
├── scripts/               → Key rotation utilities, consent manifest generators, and maintenance helpers
├── tests/                 → Pytest suites covering CLI commands, API endpoints, and exporter logic
├── docs/                  → Guides, audit artefacts, and change history
└── results/               → Output directory for generated artefacts (gitignored)
```

The runtime dependencies declared in `requirements.txt` are limited to the packages needed for the CLI and web server: Flask and Flask-Login for the UI, Jinja2 for templating, Requests and urllib3 for network calls, python-dotenv for configuration loading, Rich for console formatting, and PyNaCl for optional signing utilities. Development tooling (Black, Ruff, Bandit, pip-audit, and Pytest) is isolated in `requirements-dev.txt` and the `dev` optional dependency group of `pyproject.toml`.

Where possible, each module reads configuration from environment variables or manifest files rather than hardcoding credentials. This design keeps the project portable across local, containerised, and CI environments.
