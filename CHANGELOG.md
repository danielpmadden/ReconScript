# Changelog

## v0.4.2 - 2024-08-05
- Added a portable `start.py` launcher with automatic virtual environment
  management, dependency installation, and browser auto-open behaviour.
- Refreshed the Flask web dashboard with live summaries, hostname support,
  improved error handling, and report links.
- Simplified Docker packaging with a slim multi-stage build that boots the UI via
  `python start.py`.
- Pinned runtime dependencies in `requirements.txt` for consistent installs
  across Windows, macOS, Linux, and Docker environments.

## v0.4.0 - 2024-04-30
- Added unified reporting pipeline with Markdown, HTML, and PDF exporters powered by WeasyPrint.
- Introduced Rich-powered CLI summary tables, `--format`, `--pdf`, and `--no-color` flags.
- Bundled comprehensive HELP.md guide, refreshed README, and published sample artefacts.
- Upgraded Docker build to optionally include PDF libraries via `INCLUDE_PDF` argument.
- Extended automated tests and CI workflow for exporter coverage and container gating.
