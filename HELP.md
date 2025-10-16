# ReconScript CLI quick reference

ReconScript ships with a fully featured command-line interface for scripted assessments. All flags are read-only and safe for approved targets.

## Basic usage
```bash
reconscript --target 203.0.113.5 --ports 80 443 8080
```

## Core flags
| Flag | Description |
| ---- | ----------- |
| `--target <IP>` | **Required.** Approved IPv4/IPv6 address to assess. |
| `--hostname <name>` | Override HTTP Host header / TLS SNI. |
| `--ports <list>` | Space-separated ports or ranges (e.g. `80 443 8000-8010`). |
| `--outfile <path>` | Save report to a custom path (format inferred by extension). |
| `--format {html,json,markdown,pdf}` | Force report format. `--pdf` acts as a shortcut. |
| `--socket-timeout <sec>` | TCP timeout (default inherited from scanner). |
| `--http-timeout <sec>` | HTTP(S) timeout for metadata collection. |
| `--max-retries <n>` | HTTP retry attempts for transient issues. |
| `--backoff <sec>` | Retry backoff factor. |
| `--throttle <sec>` | Delay between TCP probes. |
| `--enable-ipv6` | Enable IPv6 resolution and scanning. |
| `--dry-run` | Produce a skeleton report without network activity. |
| `--no-browser` | Skip automatic opening of HTML reports. |
| `--no-color` | Disable Rich-coloured console summaries. |
| `--verbose` / `--quiet` | Adjust logging verbosity. |

## Output formats
- **HTML** (default): interactive report with links to served assets via `/results/<file>.html`.
- **Markdown**: portable text for internal wikis.
- **JSON**: machine-readable summary for automation.
- **PDF**: printable deliverable (requires WeasyPrint dependencies).

## Tips
- Combine `--outfile results/acme.html --format html` to align with your retention policy.
- Use `--dry-run` during change management reviews to demonstrate planned actions without touching the network.
- The CLI respects `.env` overrides for `RESULTS_DIR`, so reports land beside UI-generated files.

See the [README](README.md) for workflow overviews and the [tests](tests/) directory for concrete usage examples.
