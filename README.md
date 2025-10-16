<p align="center">
  <img src="https://img.shields.io/badge/Language-Python_3.9–3.13-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Framework-Flask-green?logo=flask&logoColor=white" alt="Flask">
  <img src="https://img.shields.io/badge/UI-HTML_+_JS-orange?logo=html5&logoColor=white" alt="HTML/JS">
  <img src="https://img.shields.io/badge/Build-Docker_+_Compose-2496ED?logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/License-MIT-yellow?logo=open-source-initiative&logoColor=white" alt="License">
  <img src="https://img.shields.io/github/v/release/YOUR_GITHUB_USERNAME/ReconScript?label=Version&color=blueviolet" alt="Version">
  <img src="https://img.shields.io/github/last-commit/YOUR_GITHUB_USERNAME/ReconScript?label=Last%20Commit&color=informational" alt="Last Commit">
  <img src="https://img.shields.io/badge/Status-Active-success?logo=git&logoColor=white" alt="Status">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/OS-Windows_|_Linux_|_macOS-lightgrey?logo=windows&logoColor=white" alt="OS">
  <img src="https://img.shields.io/badge/CLI-Compatible-critical?logo=console&logoColor=white" alt="CLI">
  <img src="https://img.shields.io/badge/Web_UI-Enabled-brightgreen?logo=google-chrome&logoColor=white" alt="Web UI">
  <img src="https://img.shields.io/github/actions/workflow/status/YOUR_GITHUB_USERNAME/ReconScript/tests.yml?label=Tests&logo=githubactions&logoColor=white" alt="Tests">
</p>

# ReconScript

ReconScript is a friendly reconnaissance toolkit for authorised defenders, blue teams, and application owners. It performs **read-only** discovery against targets you are permitted to assess, then produces clean HTML/Markdown/JSON/PDF reports that are easy to share internally or with stakeholders.

> **Authorised use only.** Always obtain written permission before scanning, obey engagement scope and rate limits, and comply with local laws. ReconScript is designed for defensive validation, not intrusion.

## Quick Start

### One-click launcher
- **macOS / Linux:** run `./start.sh`
- **Windows:** double-click `start.bat`
- The launcher creates a virtual environment (when needed), installs pinned dependencies from `requirements.txt`, starts the Flask UI, waits for the `/health` endpoint to turn green, and opens <http://127.0.0.1:5000/> automatically. Live logs stream to `results/latest.log`.

### Python workflow
```bash
python3 start.py
```
- Uses `.env` (if present) for defaults such as `DEFAULT_PORT` or `RESULTS_DIR`.
- Auto-detects Docker, WSL, or bare-metal environments and selects the right host binding.
- Opens the ReconScript dashboard in your default browser once the health check passes.

### Docker
```bash
docker compose up --build
# or manually
# docker build -t reconscript .
# docker run --rm -p 5000:5000 -v "$(pwd)/results:/app/results" reconscript
```
Docker images honour the same `.env` settings. Reports appear under the mounted `results/` directory and are also accessible via `/results` in the UI.

## Example commands
- Launch a quick localhost scan from the UI: use the “Quick Test” button (127.0.0.1 on ports 3000 & 443).
- Generate a Markdown report via CLI:
  ```bash
  reconscript --target 203.0.113.5 --ports 80 443 8080 --format markdown
  ```
- Export PDF without network activity (dry run):
  ```bash
  reconscript --target example.org --dry-run --pdf
  ```
- Install/update dependencies explicitly:
  ```bash
  python install_dependencies.py
  ```

## Web dashboard
- Automatic readiness polling with a “Preparing scan engine…” status indicator.
- Live progress via Server-Sent Events and a Rich-styled console log.
- Report library at `/results` serving HTML reports directly from the `results/` folder.

## CLI overview
A concise flag summary lives in [HELP.md](HELP.md). Highlights:
- `--target` (required): approved IPv4/IPv6 target.
- `--hostname`: override HTTP Host/TLS SNI.
- `--ports`: space-separated ports or ranges.
- `--format` / `--pdf`: control report format.
- `--dry-run`, `--throttle`, `--enable-ipv6`, `--verbose`/`--quiet` for runtime tuning.

All reports are saved beneath the configured `RESULTS_DIR` (default `results/`). The CLI and UI share the same scanning engine and Rich-formatted logging.

## Configuration
ReconScript reads optional defaults from `.env`:
```
DEFAULT_PORT=5000
RESULTS_DIR=results
```
Additional environment variables (for example `RUNNING_IN_DOCKER=1`) can help the launcher detect containerised deployments.

## Troubleshooting
- **Dependencies missing:** rerun `python install_dependencies.py --force`.
- **PDF export fails in Docker:** ensure Cairo/Pango libraries are installed; the provided Dockerfile already includes them.
- **Browser did not open:** when running in Docker the launcher prints the URL instead of auto-opening. In WSL, install `wslview` for seamless launching.

## Help
- [HELP.md](HELP.md) contains detailed CLI usage examples.
