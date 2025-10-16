<!-- # Modified by codex: 2024-05-08 -->

# ReconScript — User Guide & Command Reference

## Overview
ReconScript is a safe, read-only web reconnaissance utility for authorized security assessments.
It performs lightweight TCP + HTTP(S) metadata scans and outputs JSON, Markdown, HTML, or PDF reports.

## Installation
```
pip install .
# optional extras
pip install .[dev]     # includes Flask for the web UI
pip install .[pdf]     # installs WeasyPrint for PDF export
# or build the container image
docker build -t reconscript .
```

## Basic Usage
```
reconscript --target 203.0.113.5
```

## Command Reference
| Flag | Purpose |
|------|----------|
| --target <hostname> | Target host/IP |
| --ports <list> | Space-separated ports (80 443 3000) |
| --outfile <path> | Output file |
| --format {json,markdown,html,pdf} | Output format (defaults to HTML) |
| --dry-run | Plan only, no network contact |
| --timeout <sec> | HTTP(S) request timeout |
| --throttle <sec> | Delay between probes |
| --ipv6 | Enable IPv6 |
| --no-color | Plain terminal output |
| --no-browser | Disable auto-open of HTML reports |
| --verbose | Verbose logs |
| --version | Show version |
| --help | Short help summary |

## Example Workflows
### Safe local test
```
docker run --rm -p 3000:3000 bkimminich/juice-shop
docker run --rm --network host -v $(pwd)/results:/app/results \
  reconscript --target 127.0.0.1 --ports 3000 \
  --outfile results/juice-report.html --format html
```

### Dry-run
```
reconscript --target example.com --dry-run --verbose
```

### Local Web UI
```
pip install .[dev]
python web_ui.py
```
Visit http://127.0.0.1:5000/ and submit a localhost or RFC1918 address. The UI
queues scans in a background thread and links directly to the generated HTML and
JSON reports. The service intentionally binds only to `127.0.0.1`.

## Ethical & Safety Notes
Authorized targets only. No intrusive actions. Throttled by default.

## Troubleshooting
- Missing ports → increase timeout.
- Permission error → check the `results/` folder permissions.
- PDF fallback → install extras via `pip install .[pdf]` or rebuild the Docker image
  with `--build-arg INCLUDE_PDF=true`.

## Credits
Author Daniel Madden  Version 0.4.0  License MIT
