# ReconScript

ReconScript is a friendly reconnaissance toolkit for authorised defenders, blue teams, and application owners. It performs **read-only** discovery against targets you are permitted to assess, then produces clean HTML/Markdown/JSON/PDF reports that are easy to share internally or with stakeholders.

> ⚠️ **Authorised use only.** Always obtain written permission before scanning, obey engagement scope and rate limits, and comply with local laws. ReconScript is designed for defensive validation, not intrusion.

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
- ✅ Automatic readiness polling with a “Preparing scan engine…” status indicator.
- ✅ Live progress via Server-Sent Events and a Rich-styled console log.
- ✅ Report library at `/results` serving HTML reports directly from the `results/` folder.

Screenshot placeholders:
- ![ReconScript dashboard placeholder](docs/screenshots/dashboard.png)
- ![ReconScript report listing placeholder](docs/screenshots/results.png)

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

## Changelog & help
- See [CHANGELOG.md](CHANGELOG.md) for release notes.
- [HELP.md](HELP.md) contains detailed CLI usage examples.
- Contributions welcome — open issues or PRs to share improvements.
