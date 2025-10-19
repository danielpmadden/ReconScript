# Roadmap

## 30-Day Objectives
- [x] Enforce environment-provided secrets for the Flask UI and consent signing flow.
- [x] Consolidate GitHub Actions into a cached matrix workflow covering Ruff, Black, and pytest.
- [x] Repair Markdown exporter fallback logic and add regression coverage for CLI reporting.
- [ ] Publish an onboarding checklist that walks operators through secret provisioning and CI expectations.
- [x] Remove vendored protocol shims in favour of upstream `requests` and `PyNaCl` packages.
- [ ] Enforce automated secret scanning (detect-secrets + trufflehog) in CI pipelines.
- [ ] Keep end-to-end coverage reports at or above 85% with explicit gating in CI.

## 60-Day Objectives
- [ ] Automate signing-key rotation with documentation for Vault/Secrets Manager integrations.
- [ ] Expand Prometheus metrics to include per-stage durations and scrape examples for popular platforms.
- [ ] Add integration tests that exercise PDF generation, metrics endpoint responses, and RBAC toggles.

## 90-Day Objectives
- [ ] Build Grafana dashboards/alerts around the exposed Prometheus metrics and publish SLO targets.
- [ ] Draft a security playbook covering credential rotation, incident response, and consent manifest audits.
- [ ] Complete an accessibility audit of the UI templates, including keyboard-only navigation reviews and contrast testing.
