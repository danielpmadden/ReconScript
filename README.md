<!-- # Modified by codex: 2024-05-08 -->

# ReconScript

ReconScript is a defensive reconnaissance assistant designed for authorised web
application assessments. It performs a concise series of **read-only checks** to
catalogue exposed services, review HTTP security posture, and capture
supporting evidence in machine-readable JSON alongside beautifully formatted
Markdown, HTML, and PDF reports.

> ReconScript is expressly intended for ethical security reviews conducted
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
- **Rich terminal summary** using colour-coded status tables for each scanned
  port (disable with `--no-color`).
- **Unified report pipeline** that renders JSON, Markdown, HTML, and PDF outputs
  using consistent templates and metadata.

## Quick Start (One-Click Launch)
ReconScript is now bundled with a portable launcher that bootstraps a virtual
environment, installs pinned dependencies, and opens the web dashboard in your
default browser.

### Windows
1. Install Python 3.9–3.13 if it is not already available on your system.
2. Double-click `start.bat` (or run `start.ps1` from PowerShell for richer output).
3. The first run may take a minute while dependencies are installed. Your browser
   will open to <http://127.0.0.1:5000/> and the scan results will be written to
   the `results/` folder automatically.

### macOS / Linux
1. Ensure Python 3.9–3.13 is on your `PATH`.
2. Run `python3 start.py` from the project directory.
3. The launcher creates `.venv/`, installs everything listed in `requirements.txt`,
   opens the UI, and stores reports in `results/`.

> **Tip:** If dependency installation fails because of permissions, re-run the
> launcher from an elevated shell (Administrator on Windows or `sudo` on Unix).

## Docker Usage

Build and run the containerised ReconScript UI with the following commands:

```bash
docker build -t reconscript .
docker run -p 5000:5000 -v "$(pwd)/results:/app/results" reconscript
```

The container exposes the Flask UI on port 5000 and persists generated reports to
your local `results/` directory via the bind mount. Browser auto-opening is
disabled inside the container — visit <http://127.0.0.1:5000/> manually.

## Local Installation (Manual Option)

The launcher covers most scenarios, but you can still install ReconScript as a
traditional Python package:

```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
pip install --no-deps .
```

For development or testing, install the optional tooling bundle:

```bash
pip install --no-deps .[dev]
```

All runtime dependencies — including WeasyPrint and its helpers — are already
pinned in `requirements.txt`. When running outside Docker you may still need the
system libraries required by WeasyPrint (Cairo, Pango, etc.). On Debian/Ubuntu
install them with:

```bash
sudo apt-get install libcairo2 libgdk-pixbuf-2.0-0 libpango-1.0-0 libpangocairo-1.0-0 libjpeg62-turbo libxml2 libxslt1.1 fonts-liberation shared-mime-info
```

### Verify Installation
Confirm the package imports cleanly and the CLI entry point is available:

```bash
python -m reconscript --help
reconscript --version
reconscript --dry-run --target 127.0.0.1
```

### Run Tests
Execute the unit tests with pytest to validate local changes:

```bash
pytest
```

## Example First-Run Output

```text
Creating isolated Python environment in .venv …
Switching to the project virtual environment …
Resolving Python requirements (this may take a moment)…
[green]Dependencies installed successfully.[/green]
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ReconScript v0.4.2           ┃
┃ Author: David █████          ┃
┃ "Automated Reconnaissance"   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
Results will be stored in /Users/alex/Projects/ReconScript/results
Starting ReconScript web UI on 127.0.0.1:5000 …
 * Serving Flask app 'reconscript.ui'
 * Debug mode: off
```

The launcher automatically opens <http://127.0.0.1:5000/> and refreshes the
browser when you initiate a scan. Reports (HTML + JSON) are written to the
timestamped files inside `results/`.

## Usage

### Web UI

The local dashboard exposes the most common ReconScript options:

- **Target IP / Range** – Accepts IPv4 or IPv6 addresses. Input validation is
  enforced before any network activity begins.
- **Hostname (optional)** – Overrides the HTTP `Host` header and TLS SNI for
  name-based services.
- **Ports** – Comma-separated ports or ranges (for example `80,443,8000-8100`).
  The UI deduplicates values and ensures they stay within 1–65535.
- **Start Scan** – Launches a background job that streams status updates,
  detailed logs, and a progress bar via Server-Sent Events.

When a scan finishes you receive:

- Real-time console log updates and a coloured progress bar.
- A summary card showing scan duration, port coverage, and findings count.
- A direct link to the generated report which opens in a new browser tab.
- Automatic HTML + JSON output saved under `results/`, ready for sharing.

### CLI (Optional)

ReconScript still ships with the original CLI for automation workflows:

```bash
reconscript --target 203.0.113.5 --hostname example.com --outfile results/scan.json
```

Use `python -m reconscript` if you prefer calling the module directly. Full
guidance remains available in [HELP.md](HELP.md).

The CLI accepts the same flags as before (`--format`, `--ports`, `--pdf`,
timeouts, throttling, etc.) and continues to write all artefacts into the
`results/` directory.
### CLI Key Options
- `--target` *(required)* – IPv4 or IPv6 address that has been approved for the
  assessment. Validation is enforced before any network activity occurs.
- `--hostname` – Host header and TLS SNI value for name-based services.
- `--ports` – Space-separated list of TCP ports to probe. Defaults to common
  web stack ports (`80 443 8080 8443 8000 3000`).
- `--outfile` – Write the report to a file (format inferred from the extension).
- `--format` / `--pdf` – Force a specific report format. By default the CLI emits
  HTML into the `results/` directory. Use `--no-browser` to disable automatic
  opening of HTML reports.
- `--socket-timeout` / `--http-timeout` – Tune socket and HTTP timeouts (in
  seconds) to accommodate slower networks.
- `--max-retries` / `--backoff` – Configure HTTP retry behaviour with
  exponential backoff for transient issues.
- `--throttle` – Delay between port probes to respect engagement rate limits.
- `--enable-ipv6` – Opt-in IPv6 resolution and scanning.
- `--dry-run` – Produce a skeleton report without making network connections.
- `--no-color` – Disable the colourised summary table for monochrome terminals.
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
  "version": "0.4.0",
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

**Why did PDF export fall back to HTML?**
: ReconScript only attempts PDF generation when WeasyPrint and its GTK
  dependencies are available. When they are absent you will see a warning and the
  HTML report is preserved instead. Use `pip install .[pdf]` locally or build the
  Docker image with `INCLUDE_PDF=true` for full PDF support.

## Ethical Operation
ReconScript never attempts authentication, credential guessing, fuzzing, or
service disruption. Nevertheless, you must:

1. Obtain written authorisation for every environment you inspect.
2. Honour organisational rate limits and maintenance windows.
3. Store collected data securely and delete it once no longer required.
4. Use `--dry-run` mode for demonstrations and configuration tests without
   touching live services.
5. Report discovered issues responsibly to the system owner.

By running ReconScript you confirm that you understand and will abide by these
principles.

## License
ReconScript is provided under the MIT License. Review the license before
redistributing or integrating the tooling into production workflows.

## Post-Merge Runbook

## Quick Start
**Windows:**
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --no-deps .[dev]
py -m reconscript --target 127.0.0.1 --ports 3000
```

**macOS/Linux:**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install --no-deps .[dev]
python3 -m reconscript --target 127.0.0.1 --ports 3000
```

The report auto-opens in your browser (`results/scan-YYYYMMDD-HHMMSS.html`).

---

## Web UI
```bash
python web_ui.py
```
Then visit:  
➡ http://127.0.0.1:5000/

Enter:
- Target (default: 127.0.0.1)
- Ports (space-separated)
- Format (HTML/JSON/MD)

Click **Run Scan** → the HTML report opens when complete.

---

## Docker Demo
```bash
docker-compose up
```
Starts OWASP Juice Shop (port 3000) + ReconScript UI on port 5000.  
Reports stored under `./results/`.

To include PDF:
```bash
docker build --build-arg INCLUDE_PDF=true -t reconscript:pdf .
```

---

## Testing
```bash
pytest -q
```
✅ All tests pass or skip gracefully (PDF skipped if GTK missing).

---
