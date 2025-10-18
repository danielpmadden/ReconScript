# Roadmap

## Planned Enhancements
- [ ] Publish automated consent manifest testing guidance in `docs/` so operators can rehearse pre-flight reviews.
- [ ] Extend the report pipeline with configurable scheduling to support recurring scans.
- [ ] Introduce optional role-based access control for the web UI to align with enterprise access policies.
- [ ] Design a REST API that mirrors CLI capabilities for remote orchestration.

## Deferred Work and Investigations
- [ ] Evaluate integrating Shodan and Censys enrichment services without compromising the read-only posture.
- [ ] Update Docker and base operating system images to the latest slim Python releases and refresh lockfiles afterwards.
- [ ] Review validation of user-supplied targets throughout the `reconscript` package to ensure strict input handling before any production deployment.
- [ ] Revisit helper scripts that invoke subprocesses to confirm arguments are sanitised and environment-aware.

## Documentation and Operational Tasks
- [ ] Capture refreshed UI screenshots for `docs/screenshots/` once the interface updates stabilise.
- [ ] Align README, HELP, and CLI reference content whenever major features ship to prevent drift.
- [ ] Add explicit environment variable tables to `docs/HELP.md` covering Docker, CLI, and web deployments.

## Security and Compliance Notes
- `bandit -r reconscript`: **Not executed** in this audit environment. Recommend running locally; prioritise findings involving input handling or unsafe subprocess usage.
- `pip-audit --requirement requirements.txt`: **Not executed**. Review reported CVEs promptly and pin patched versions.
- Docker images should include metadata labels (maintainer, version, description) and consider enabling a container health check in future iterations.
- No hardcoded secrets were identified during the documentation review; continue relying on environment variables and manifest files for sensitive values.

## Dependency and Compatibility Considerations
- Runtime dependencies remain pinned in `requirements.txt` and `pyproject.toml`. Monitor Flask, Requests, and urllib3 for security updates; refresh pins quarterly.
- Development dependencies now include `bandit`, `ruff`, and `pip-audit` to align with the CI workflow.
- The project targets Python 3.9 through 3.13. Validate support for upcoming Python releases annually and update classifiers accordingly.

## Audit Summary
- Dependencies checked and aligned with pinned versions for repeatable installs.
- Deprecated packaging fields replaced with modern SPDX-compatible settings per Python.org guidance for 2026.
- Security tools recommended but not executed; see notes above for follow-up actions.
- CI workflow updated to run linting, tests, and security audits for continuous review.
- No functional code changes were introduced during this audit.
