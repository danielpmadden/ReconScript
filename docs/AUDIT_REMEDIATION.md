# Audit Remediation Mapping

Each finding from the previous engineering audit is addressed below with the implemented fix, validation strategy, and expected outcome.

## F-001 – Markdown fallback returned incomplete documents
- **Root cause:** The Python fallback in `reconscript/reporters.py` returned early without building full Markdown when Jinja2 templates were unavailable.
- **Code-level fix:** Added `_build_markdown_context` and `_render_markdown_sections` helpers to assemble sections deterministically and ensure metadata is appended even without Jinja2.
- **Tests added:** `tests/test_reporters.py::test_render_markdown_fallback_contains_sections` verifies all sections render, and `test_write_report_markdown` exercises the CLI writer path.
- **CI/Docs/Infra:** Included the reporter tests in the unified CI matrix; README now references Markdown export behaviour.
- **Risk reduction:** Guarantees CLI exports remain reviewable in air-gapped environments, restoring trust in audit artefacts.

## F-002 – Presentation and data shaping were intertwined
- **Root cause:** `render_markdown` handled both data normalization and presentation formatting, complicating reuse.
- **Code-level fix:** Split the logic into `_build_markdown_context` and `_render_markdown_sections`, enabling targeted unit tests and future renderer reuse.
- **Tests added:** Same reporter tests confirm the separated pipeline stays in sync.
- **CI/Docs/Infra:** Documented the Markdown pipeline in the remediation guide for future contributors.
- **Risk reduction:** Improves maintainability by isolating transformations, reducing regression probability when report fields change.

## F-003 – Exporters and CLI lacked regression coverage
- **Root cause:** No pytest modules exercised Markdown rendering or CLI formatting flows.
- **Code-level fix:** Added reporter tests and `tests/test_cli_markdown.py` to invoke `cli.main` with `--format markdown`.
- **Tests added:** New tests run automatically in CI and validate generated artefacts.
- **CI/Docs/Infra:** CI matrix executes pytest across Python 3.9/3.11; docs highlight the command sequence to replicate locally.
- **Risk reduction:** Prevents silent export regressions by enforcing guardrails before release.

## F-004 – Duplicate CI workflows without caching
- **Root cause:** `ci.yml` and `lint.yml` duplicated installs and skipped caching, slowing feedback.
- **Code-level fix:** Removed redundant workflows and retained `.github/workflows/ci-matrix.yml` with pip caching, lint/test steps, and coverage upload.
- **Tests added:** CI now runs the expanded pytest suite automatically.
- **CI/Docs/Infra:** README references the matrix workflow; caching drastically shortens rerun latency.
- **Risk reduction:** Speeds up reviews and reduces drift risk between lint/test definitions.

## F-005 – Default UI credentials and Flask secret shipped in repo
- **Root cause:** `_load_user_credentials` and `_load_secret_key` fell back to `admin/changeme` and `keys/dev_flask_secret.key`.
- **Code-level fix:** Require `ADMIN_USER`, `ADMIN_PASSWORD`, and `FLASK_SECRET_KEY_FILE` to be set; block developer secrets unless `ALLOW_DEV_SECRETS=true`.
- **Tests added:** `tests/conftest.py` fixture seeds secure test-only values to exercise the stricter loaders.
- **CI/Docs/Infra:** README/SECURITY guide operators through secret provisioning; Docker build removes developer keys by default.
- **Risk reduction:** Eliminates trivial takeover paths by forcing strong credentials and unique Flask secrets.

## F-006 – Consent/report signing keys defaulted to bundled dev keys
- **Root cause:** `reconscript/consent.py` read `keys/dev_ed25519.*` when environment overrides were absent.
- **Code-level fix:** Introduced `_resolve_key_path` and `_guard_key_path` to require explicit `CONSENT_PUBLIC_KEY_PATH`/`REPORT_SIGNING_KEY_PATH` values and optionally block sample keys.
- **Tests added:** Global fixture configures env vars for tests; consent validation suite reuses dev keys only when `ALLOW_DEV_SECRETS` is set.
- **CI/Docs/Infra:** SECURITY.md details rotation cadence and storage expectations.
- **Risk reduction:** Prevents forged manifests by ensuring deployments load verified signing material.

## F-007 – Lack of telemetry on scan performance
- **Root cause:** There was no metrics instrumentation to observe scan durations or queue depth, hindering performance tuning.
- **Code-level fix:** Added `reconscript/metrics.py` with Prometheus histograms/counters and wired them into `run_recon`.
- **Tests added:** Metrics leveraged indirectly by CLI/report tests; further integration tests planned at 60-day milestone.
- **CI/Docs/Infra:** README advertises the `/metrics` endpoint; roadmap schedules dashboard creation.
- **Risk reduction:** Operators can now detect slow or failing scans via telemetry before SLOs are breached.

## F-008 – Limited observability and structured logging gaps
- **Root cause:** UI actions and scan lifecycle events lacked structured logging, and no metrics endpoint existed.
- **Code-level fix:** Added structured `LOGGER.info`/`LOGGER.error` calls in `reconscript/ui.py`, exposed `/metrics`, and integrated Prometheus payload responses.
- **Tests added:** CLI/report tests confirm instrumentation does not regress functionality; future integration coverage tracked on roadmap.
- **CI/Docs/Infra:** Metrics exposed for scraping; Docker healthcheck ensures `/healthz` stays responsive.
- **Risk reduction:** Enhances incident response with consistent event streams and monitoring hooks.

## F-009 – Documentation failed to enforce secret replacement
- **Root cause:** README/SECURITY.md implied but did not mandate replacing developer secrets.
- **Code-level fix:** Updated README quick start to require explicit environment exports and expanded SECURITY.md with rotation guidance and monitoring tips.
- **Tests added:** N/A (documentation change).
- **CI/Docs/Infra:** Docs now align with runtime enforcement; roadmap includes onboarding checklist.
- **Risk reduction:** Reduces misconfiguration risk by making secret provisioning an explicit deployment step.

## F-010 – Dependency governance lacked metrics dependency
- **Root cause:** Prometheus instrumentation was absent from pinned dependencies, risking runtime import errors.
- **Code-level fix:** Added `prometheus-client` to `requirements.txt`, `requirements-dev.txt`, and `requirements.lock`.
- **Tests added:** CI installs the new dependency across Python versions.
- **CI/Docs/Infra:** Matrix workflow caches the dependency; README mentions metrics support.
- **Risk reduction:** Ensures telemetry code loads deterministically across environments.

## F-011 – UI accessibility gaps
- **Root cause:** Templates lacked skip links, focus outlines, and descriptive helper text for assistive technologies.
- **Code-level fix:** Enhanced `layout.html`, `index.html`, and `login.html` with skip-link navigation, ARIA labelling, focus styles, and contrast-friendly hints.
- **Tests added:** Manual verification documented in accessibility roadmap; automated tests slated for 90-day audit.
- **CI/Docs/Infra:** Accessibility improvements captured in roadmap milestones.
- **Risk reduction:** Improves UX for keyboard and screen-reader users, aligning with enterprise accessibility standards.

## F-012 – Container image bundled secrets and lacked healthcheck
- **Root cause:** Dockerfile copied `keys/` unconditionally and provided no runtime health signal.
- **Code-level fix:** Added `INCLUDE_DEV_KEYS` build arg to strip sample keys by default and configured a Python-based `HEALTHCHECK` hitting `/healthz`.
- **Tests added:** Covered indirectly via CLI dry-run tests; integration tests planned for metrics and health endpoints.
- **CI/Docs/Infra:** README instructs operators to pass secrets at runtime; Dockerfile change improves readiness reporting.
- **Risk reduction:** Prevents accidental secret leakage in images and enables orchestrators to detect unhealthy containers.

## F-013 – Maintainability risks from drift and missing automation
- **Root cause:** Duplicate workflows, absent exporter tests, and undocumented remediation steps increased drift risk.
- **Code-level fix:** Unified CI, added reporter/CLI tests, and captured remediation mapping plus a 30/60/90 roadmap.
- **Tests added:** New pytest modules and fixtures now run automatically.
- **CI/Docs/Infra:** Documentation updates plus the roadmap and ongoing audit plan (below) set expectations for future maintenance.
- **Risk reduction:** Provides a sustainable quality bar and reduces the chance of regressions escaping into production.

## Ongoing Audit Plan
- **Dependency hygiene:** Run `pip-audit`, `bandit`, and `gitleaks` weekly; regenerate `requirements.lock` after dependency bumps.
- **Continuous linting:** The CI matrix enforces Ruff/Black on every push; keep local pre-commit hooks aligned with the same config.
- **Key rotation cadence:** Rotate UI credentials and signing keys every 90 days, documenting each rotation in the ops logbook.
- **Observability KPIs:** Track `recon_scans_total` (failures < 2%), `recon_scan_duration_seconds` (p95 < 90s), and `recon_scan_open_ports` anomaly spikes via dashboards and alerts.
