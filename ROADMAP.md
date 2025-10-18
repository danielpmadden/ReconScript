# Roadmap

## Near Term
- [ ] Document automated consent manifest testing flow in `docs/`.
- [ ] Publish example CI pipeline for Docker image scanning.
- [ ] Add screenshots gallery once refreshed UI assets are available.

## Future Enhancements
- [ ] Future Enhancement: integrate Shodan and Censys enrichment services.
- [ ] Future Enhancement: implement background scheduling for queued scans.
- [ ] Future Enhancement: add optional role-based access control to the web UI.
- [ ] Future Enhancement: publish a REST API for remote automation.

## Observations from Audit
- [ ] Future Fix: review handling of user-supplied targets for strict validation (see `reconscript` package) before production use.
- [ ] Future Fix: confirm subprocess usage in helper scripts sanitizes all parameters.
- [ ] Future Enhancement: update Docker base image to the latest slim Python release and rebuild lock files.
- [ ] Future Enhancement: align documentation references (README, HELP) whenever major features ship.
- [ ] Future Fix: execute `bandit -r reconscript` and capture baseline findings once tooling is available in the environment.

## Maintenance Notes
- Track dependency updates using `pyproject.toml` and `requirements.lock` for reproducible builds.
- Run `bandit -r reconscript` and `pip-audit` regularly; address any findings before releases.
- Encourage contributors to review `docs/SECURITY.md` before deploying externally.
