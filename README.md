# ReconScript
*Safe, authorized reconnaissance with human-friendly reporting.*

![Python](https://img.shields.io/badge/Python-3.9%E2%80%933.13-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web%20UI-000000?logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

> ReconScript is Daniel Madden's ethical reconnaissance lab: a calm, non-destructive framework for inspecting approved targets and producing polished reports without touching exploitation tooling.

---

## Preview
A current UI capture lives at `docs/screenshots/preview.png.placeholder.txt`. Follow the instructions inside to generate the screenshot locally without committing binaries.

---

## Overview
- **Purpose-built for safety:** TCP connect probing, HTTP/TLS metadata, and consent manifest tracking keep operations auditable.
- **Multiple delivery modes:** Launch via CLI, Flask web UI, or Docker for quick demos and workshops.
- **Reporting your way:** Export HTML dashboards, JSON artifacts, Markdown briefs, or PDFs for stakeholders.
- **Ethical guardrails:** Development keys and manifests make it clear what to replace before any production use.

---

## Quickstart
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/ReconScript.git
cd ReconScript
./start.sh
```
Then open <http://127.0.0.1:5000> in your browser.

**Windows:** run `start.bat`.  
**Docker:** `docker compose up` or build the image (`docker build -t reconscript .`) and run it with a mounted `results/` volume.

---

## Usage
### Web UI
1. Enter the approved hostname or IP.
2. Optionally adjust port selections and output format.
3. Launch the scan and track progress live.
4. Retrieve generated reports from the UI or the `results/` directory.

### CLI
```bash
python -m reconscript --target 127.0.0.1 --ports 80 443 --format html
```
Reports are timestamped within `results/<scan-id>/` and may include signatures when enabled.

---

## Repository Map
```
├─ reconscript/          # Core scanners, report builders, and Flask application
├─ templates/            # HTML and Markdown templates
├─ scripts/              # Developer utilities (key manifests, helpers)
├─ tests/                # Pytest suites
├─ results/              # Generated reports (gitignored)
└─ docs/                 # Help, changelog, roadmap, and security notes
```

Key entry points:
- `start.py` orchestrates environment detection and launches the UI.
- `install_dependencies.py` ensures required packages are installed.
- `docker-compose.yml` runs the full stack with persistent report storage.

---

## Tooling & Automation
- `requirements.txt` — runtime dependencies.
- `requirements-dev.txt` — local development helpers.
- `.github/workflows/ci.yml` — existing test and build automation.
- `.github/workflows/lint.yml` — optional formatting and static analysis reminders.

Run these commands locally when contributing:
```bash
python -m pip install -r requirements-dev.txt
black .
flake8
bandit -r reconscript
pytest
```

---

## Documentation Hub
- [docs/HELP.md](docs/HELP.md) — quick setup, troubleshooting, and commands.
- [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) — deep-dive flags and output formats for the CLI.
- [docs/CHANGELOG.md](docs/CHANGELOG.md) — historical highlights.
- [docs/SECURITY.md](docs/SECURITY.md) — usage guardrails and disclosure guidance.
- [ROADMAP.md](ROADMAP.md) — upcoming enhancements and audit observations.

---

## Safety & Consent
ReconScript is for educational labs and explicit engagements only. Replace development keys in `keys/`, review manifests before scans, and never probe systems without written authorization. Reports include hashes and optional signatures for accountability.

---

## Contributing
1. Fork the repository and create a feature branch.
2. Follow PEP 8; run Black, Flake8, Bandit, and pytest before opening a PR.
3. Document new behaviors in the README and docs as needed.
4. Submit a pull request summarizing validation steps and scope approvals.

---

## License
Released under the MIT License. See `LICENSE` for details.

---

## Author
**Daniel Madden**  
IT Professional | Technology Enthusiast | Builder of Experiments  
“Not a software engineer — just a guy who loves all things tech.”
