# ReconScript — User Guide & Command Reference

## Overview
ReconScript is a safe, read-only web reconnaissance utility for authorized security assessments.
It performs lightweight TCP + HTTP(S) metadata scans and outputs JSON, Markdown, HTML, or PDF reports.

## Installation
```
pip install .
# or
docker build -t reconscript .
```

## Basic Usage
```
reconscript --target example.com
```

## Command Reference
| Flag | Purpose |
|------|----------|
| --target <hostname> | Target host/IP |
| --ports <list> | Comma-separated ports |
| --outfile <path> | Output file |
| --format {json,markdown,html,pdf} | Output format |
| --dry-run | Plan only, no network contact |
| --timeout <sec> | Request timeout |
| --throttle <sec> | Delay between probes |
| --ipv6 | Enable IPv6 |
| --no-color | Plain terminal output |
| --verbose | Verbose logs |
| --version | Show version |
| --help | Short help summary |

## Example Workflows
### Safe local test
```
docker run --rm -p 3000:3000 bkimminich/juice-shop  
docker run --rm --network host -v $(pwd)/results:/app/results \
  reconscript --target 127.0.0.1 --ports 3000 \
  --outfile results/juice-report.md --format markdown
```

### Dry-run
```
reconscript --target example.com --dry-run --verbose
```

## Ethical & Safety Notes
Authorized targets only. No intrusive actions. Throttled by default.

## Troubleshooting
- Missing ports → increase timeout.
- Permission error → check output folder.
- PDF missing → rebuild Docker with --build-arg INCLUDE_PDF=true.

## Credits
Author Daniel Madden  Version 0.4.0  License MIT
