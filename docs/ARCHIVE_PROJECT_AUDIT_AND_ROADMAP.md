# Project Audit & Roadmap Report

## 1. Executive Summary
ReconScript is a Python 3.9+ command-line toolkit that performs read-only reconnaissance of authorised web assets, bundling TCP probing, HTTP metadata collection, report generation, and PDF export within a single package and Docker image.【F:README.md†L3-L140】【F:pyproject.toml†L5-L56】The codebase shows solid modularity and thoughtful safety defaults, backed by CI that lint-tests, builds containers, and scans images; however, dependency hygiene, scalability, and observability controls lag behind production expectations.【F:.github/workflows/build.yml†L1-L110】Overall readiness score: **68/100** (upper pre-production). Top strengths: (1) comprehensive documentation and operator guidance,【F:README.md†L32-L175】 (2) defensive input validation and safe network defaults in the scanner pipeline,【F:reconscript/scanner.py†L29-L208】 and (3) mature CI/CD workflow with linting, testing, containerisation, and Trivy scanning.【F:.github/workflows/build.yml†L1-L110】 Top weaknesses: (1) lack of pinned/locked dependencies and optional extras separation leading to fragile builds,【F:pyproject.toml†L15-L26】 (2) sequential, single-threaded scan architecture without observability or metrics for scaling,【F:reconscript/scanner.py†L139-L173】 and (3) limited runtime hardening—no rate-limit telemetry, secret scanning, or structured logging beyond basics.【F:reconscript/core.py†L87-L122】【F:README.md†L142-L173】

## 2. Codebase Integrity
- Modules are well-separated (CLI, orchestration, scanner, reporters) with docstrings, but some functions (e.g., `main`, `_render_summary_table`) approach 40+ lines and could be decomposed for readability.【F:reconscript/cli.py†L232-L344】
- Input validators (`_port`, `_positive_float`, etc.) guard against unsafe parameters, yet `run_recon`’s `ports` argument lacks an explicit type hint and is passed directly from argparse, obscuring intent.【F:reconscript/cli.py†L242-L254】【F:reconscript/core.py†L34-L71】
- The fallback `Console`/`Table` classes ensure CLI resilience but duplicate behaviour; consider extracting to utilities to avoid inline class definitions.【F:reconscript/cli.py†L11-L55】
- `_timeout_wrapper` monkey patches `requests.Session.request`, which can surprise maintainers and complicate type checking; prefer a `session.request` wrapper or adapter subclass.【F:reconscript/scanner.py†L103-L137】
- Error handling primarily covers `ValueError`/`RuntimeError`; network operations return dicts with `"error"` keys rather than raising, so callers must inspect results—consider explicit result objects to avoid silent failures.【F:reconscript/scanner.py†L254-L284】【F:reconscript/core.py†L98-L116】
- Comments and docstrings are present, though reporter helpers and CLI summary logic would benefit from inline explanations around HTML escaping and formatting choices.【F:reconscript/reporters.py†L82-L206】
- No obvious dead code; exports are limited via `__all__` to keep APIs tidy.【F:reconscript/reporters.py†L272-L278】

## 3. Dependency & Build Health
- Core dependencies: `requests>=2.25`, `rich>=13`, `weasyprint>=61`; dev extras: `pytest>=7.0`, `responses>=0.25`, `flake8>=6.0`.【F:pyproject.toml†L15-L26】
- No upper bounds or lock file (e.g., `poetry.lock`, `requirements.txt`), increasing risk of supply-chain regressions. WeasyPrint is heavy and should be optional rather than a mandatory install.
- Dockerfile builds a wheel in a multi-stage pipeline but still relies on latest pip-resolved versions at build time, inheriting the same variability.【F:Dockerfile†L15-L91】
- GitHub Actions caches pip downloads but not wheels; consider leveraging `pip-tools` or `uv` lock files for reproducibility.【F:.github/workflows/build.yml†L37-L49】

## 4. Architecture & Design
- Architecture is a single CLI application with orchestrator (`core`) delegating to scanner utilities and report renderers, following a clean separation between I/O (CLI/reporters) and network logic (scanner).【F:reconscript/core.py†L34-L122】【F:reconscript/reporters.py†L17-L206】
- Tight coupling exists between CLI and reporters via direct imports; consider dependency injection to ease testing and alternate UIs.【F:reconscript/cli.py†L53-L78】
- The scanner sequentially loops over ports and addresses, lacking concurrency or asynchronous support, which constrains throughput at scale.【F:reconscript/scanner.py†L139-L172】
- Configuration is entirely flag-driven; no support for config files or environment overrides beyond Docker defaults, limiting automation flexibility.【F:reconscript/cli.py†L101-L200】【F:Dockerfile†L63-L68】
- Sensitive parameters (timeouts, throttle) default to safe values, but there is no mechanism to persist per-environment policy.

## 5. Security Audit
- No hardcoded secrets found; credentials are absent. User agent clearly signals defensive intent.【F:reconscript/scanner.py†L43-L44】
- Target validation enforces IP-only scanning, reducing scope creep.【F:reconscript/scanner.py†L62-L86】
- TLS certificate retrieval disables hostname checking (by design) but exposes certificate metadata even if validation fails; document rationale and add logging for reused certificates.【F:reconscript/scanner.py†L286-L314】
- Robots and HTTP fetchers guard against external redirects to avoid scanning out-of-scope hosts, which is good practice.【F:reconscript/scanner.py†L244-L333】
- Security posture score: **72/100**. Mitigation priorities: add secret scanning (Gitleaks/GH secret scanning), incorporate Bandit/Snyk for static security analysis, and validate/report when retries exhaust or responses contain large payloads.

## 6. Testing & QA
- Tests cover CLI argument flow, report exporters, and helpers, but there is no explicit coverage reporting or integration tests for network operations beyond mocked responses.【F:tests/test_cli.py†L1-L73】
- CI runs flake8, pytest (quiet mode), docker build, runtime dry-run, and Trivy scan, showing mature gating.【F:.github/workflows/build.yml†L55-L104】
- Missing: coverage measurement, mutation/fuzz tests for parser, and end-to-end scan using mocked sockets.
- Plan to reach 80% coverage: introduce `pytest-cov`, add socket/http fixtures to simulate port states, and integrate `responses` library for HTTP/TLS flows.

## 7. Documentation & Onboarding
- README provides installation, usage, options, troubleshooting, ethics, and licensing sections, offering strong onboarding material.【F:README.md†L32-L175】
- HELP.md and CHANGELOG exist (not reviewed here) indicating change history discipline.
- Missing: architecture overview diagram, contribution guidelines, and API docs for modules.
- Suggest reorganising docs into `/docs` with quickstart, development guide, threat model, and generated CLI reference (e.g., via `sphinx` or `mkdocs`).

## 8. Performance & Scalability
- TCP scanning and HTTP probing run serially; high-latency environments will prolong scans. Parallel sockets with asyncio or thread pools could improve throughput.【F:reconscript/scanner.py†L139-L172】
- No caching or deduplication beyond port set normalization; repeated runs rely on retries but no exponential scheduling beyond `requests` adapter.
- No metrics/log aggregation for scan duration or success counts, hindering capacity planning.【F:reconscript/core.py†L94-L117】
- Current design suitable for small scopes; for 10× load, expect linear slowdown without concurrency or distributed workers.

## 9. DevOps & Deployment
- Multi-stage Dockerfile builds and tests, runs as non-root, and copies documentation—strong baseline.【F:Dockerfile†L6-L102】
- `.dockerignore` excludes tests, but builder stage copies them; ensure alignment to avoid bloating contexts (currently tests are ignored yet manually copied).【F:.dockerignore†L1-L12】【F:Dockerfile†L33-L38】
- docker-compose offers a dry-run profile only; add parametrised services for real scans and environment variables for throttling.【F:docker-compose.yml†L1-L18】
- Pipeline publishes images to GHCR with dated tags but lacks signing (cosign) and SBOM generation.

## 10. Maintainability & Team Ergonomics
- Consistent naming and module boundaries, but central orchestration exposes many scanner internals via `__all__`, risking tight coupling.【F:reconscript/core.py†L124-L128】
- Commit history not inspected; recommend adopting Conventional Commits and PR templates.
- No issue/PR templates or CODEOWNERS detected; bus factor remains unknown.
- Suggest enforcing pre-commit hooks (black, isort, flake8) and adding `CONTRIBUTING.md` for onboarding expectations.

## 11. Strategic Roadmap
| Phase | Objective | Key Actions | Deliverables | Priority |
|-------|-----------|-------------|--------------|----------|
| Phase 1 | Stabilization | Pin dependencies with lock file, refactor CLI/reporting helpers for clarity, add pytest coverage w/ network mocks | Stable main branch with reproducible builds | 🔴 High |
| Phase 2 | Modernization | Introduce async/threaded scanner, split PDF dependency into optional extra, add config file/env overrides | v0.5.0 “modern scan core” release | 🟠 Medium |
| Phase 3 | Security Hardening | Integrate Bandit/Gitleaks, enable Dependabot/Snyk, add CI secret scanning and SARIF upload | Security baseline dashboard | 🟢 Medium |
| Phase 4 | Observability | Add structured logging, metrics (Prometheus/export JSON stats), and configurable telemetry hooks | Monitor-ready CLI/container | 🟢 Medium |
| Phase 5 | Scaling & UX | Build report viewer UI, batching engine, and dashboard exports; add SBOM + signed images | Production-grade 1.0.0 milestone | 🟢 Low |

*Estimates*: Phase 1 (2-3 weeks), Phase 2 (3-4 weeks, depends on Phase 1), Phase 3 (parallel to Phase 2, ~2 weeks), Phase 4 (2 weeks post Phase 2), Phase 5 (6+ weeks after telemetry foundation).

## 12. Risk Matrix
| Severity | Description | Affected Area | Mitigation |
|----------|-------------|---------------|------------|
| Critical | Dependency drift due to unpinned versions | Build system | Introduce lock files and Dependabot | 
| High | Sequential scans unable to meet SLA for larger scopes | Scanner architecture | Implement concurrency and throttling controls | 
| Medium | Missing security/static analysis in CI | CI/CD | Add Bandit, safety checks, and secret scanning | 
| Low | Inline CLI helper classes obscure reuse | Code organization | Extract to shared utilities with tests | 

## 13. Recommendations Summary
1. Generate a deterministic dependency lock (e.g., `pip-tools` or `uv`) and split PDF support into an optional extra to slim default installs.【F:pyproject.toml†L15-L26】
2. Break down large CLI/reporting functions into smaller units and add type hints for config inputs to improve readability and static analysis.【F:reconscript/cli.py†L232-L344】【F:reconscript/core.py†L34-L71】
3. Replace the `requests` monkey patch with an adapter subclass or per-call timeout to avoid hidden behaviour and ease testing.【F:reconscript/scanner.py†L103-L137】
4. Add pytest coverage tooling and extend tests to cover scanner networking via fakes/mocks, targeting 80%+ coverage.【F:tests/test_cli.py†L1-L73】
5. Introduce async/threaded scanning to parallelise port checks and HTTP requests for better scalability.【F:reconscript/scanner.py†L139-L284】
6. Implement structured logging and metrics emission (JSON logs, Prometheus counters) to support observability and auditing.【F:reconscript/core.py†L87-L119】
7. Expand CI with Bandit, pip-audit, and secret-scanning steps; publish SARIF results for developer feedback.【F:.github/workflows/build.yml†L55-L104】
8. Add CONTRIBUTING guide, architecture overview, and module API reference to reduce onboarding friction.【F:README.md†L32-L175】
9. Generate SBOM and sign container images (cosign) before publishing to GHCR for supply-chain integrity.【F:.github/workflows/build.yml†L81-L110】
10. Provide configuration files/env var mapping to reuse scanner settings across deployments, improving automation ergonomics.【F:reconscript/cli.py†L101-L200】【F:Dockerfile†L63-L68】

**Overall Recommendation:**  
Current state: Pre-Production  
Next milestone: Target v0.5.0 readiness in ~2 months (post-Phase 2 & 3 completion).
