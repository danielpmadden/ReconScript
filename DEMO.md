<!-- # Modified by codex: 2024-05-08 -->
# ReconScript Demonstration Guide

## Quick CLI run (HTML auto-open)
```bash
python -m venv .venv
source .venv/bin/activate
pip install --no-deps .
python -m reconscript --target 127.0.0.1 --ports 3000 --format html --outfile results/demo.html
```
The CLI writes `results/demo.html` and automatically opens it in your default browser. Disable the
browser step with `--no-browser`.

## Local web UI
```bash
pip install --no-deps .[dev]
python web_ui.py
```
Navigate to <http://127.0.0.1:5000/>, choose a localhost/RFC1918 target, and watch the job complete.
Reports are written to the shared `results/` directory.

## Docker Compose demo
```bash
make demo       # launches Juice Shop + optional runner (HTML output in ./results)
make demo-ui    # launches Juice Shop + local-only ReconScript UI on 127.0.0.1:5000
```
Both targets bind only to loopback interfaces. Results from container runs appear under `./results/`.
