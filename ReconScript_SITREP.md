# ReconScript SITREP

## Executive Summary
- ReconScript presents a solid modular layout with ethical safeguards, but key delivery and security controls are brittle; current readiness for production release is **58/100**.
- The build pipeline is blocked by a missing CLI feature, and security scanning is ineffective due to permissive CI settings, requiring immediate remediation before shipment.

## Critical Findings
- **Missing `--dry-run` support breaks automated runs** – Both `docker-compose.yml` and the GitHub Actions workflow call `--dry-run`, yet the CLI parser exposes no such flag, causing container and CI executions to fail with argument errors.【F:docker-compose.yml†L1-L11】【F:.github/workflows/build.yml†L52-L55】【F:reconscript/cli.py†L67-L134】

## High / Medium / Low Findings
### High Severity
- **Container image scanning never fails builds** – The Trivy step forces `--exit-code 0`, so even HIGH/CRITICAL CVEs will not halt the pipeline, masking serious vulnerabilities during releases.【F:.github/workflows/build.yml†L56-L58】
- **HTTP probe can follow unscoped redirects** – `probe_http_service` enables `allow_redirects=True`, permitting targets to send the scanner to arbitrary hosts (e.g., metadata services) and undermining scope restrictions stated in the README.【F:reconscript/scanner.py†L236-L259】【F:README.md†L52-L65】

### Medium Severity
- **HTTP session never closed** – `run_recon` creates a long-lived `requests.Session` but never closes it, leaving sockets open in longer runs or integrations.【F:reconscript/core.py†L66-L107】
- **`outfile` writes lack filesystem safety** – When `--outfile` points to a non-existent directory, `Path.write_text` raises `FileNotFoundError`, which escapes the CLI’s narrow exception handler and terminates the tool without a clear message.【F:reconscript/core.py†L100-L105】【F:reconscript/cli.py†L166-L183】
- **Release metadata drift** – Runtime image labels and example artefacts advertise version `0.3.0` while the package exports `0.2.0`, making provenance auditing unreliable.【F:Dockerfile†L40-L45】【F:examples/findings.json†L1-L25】【F:reconscript/__init__.py†L1-L8】
- **Automated tests skip core workflows** – The test suite only exercises helper utilities (`check_security_headers`, `parse_cookie_flags`, `generate_findings`) and provides no coverage for the CLI, orchestration, or network primitives.【F:tests/test_helpers.py†L1-L82】

### Low Severity
- **Redundant configuration knobs** – `ScanConfig` stores `throttle`, yet the only caller passes throttle separately; the field is otherwise unused, signalling configuration drift.【F:reconscript/scanner.py†L46-L171】
- **Environment defaults unused** – Runtime-stage environment variables (`RECONSCRIPT_DEFAULT_*`) are never read by the application, adding noise and confusion for operators expecting override support.【F:Dockerfile†L46-L51】【F:reconscript/scanner.py†L61-L260】
- **No `.dockerignore`** – The Docker build context includes tests and repository metadata, slowing builds and leaking unnecessary artefacts into cache layers.

## Redundancy & Consistency Notes
- `DEFAULT_PORTS` and `HTTP_PORTS` duplicate the same tuple, indicating maintainability debt if the lists ever diverge.【F:reconscript/scanner.py†L23-L34】
- Documentation artefacts disagree on schema and version fields (`version` vs `tool_version`), complicating automated report ingestion.【F:examples/sample_report.json†L1-L61】【F:examples/findings.json†L1-L25】
- `PYTHON_REVIEW.md` still analyses the legacy monolithic script and warns about duplicate logic that no longer exists, creating reviewer confusion.【F:PYTHON_REVIEW.md†L1-L65】

## Security Review Summary
- Network operations remain read-only, but redirect handling, verbose body capture, and logging of full serialized reports could expose sensitive partner data beyond intended scope.【F:reconscript/scanner.py†L236-L259】【F:reconscript/core.py†L95-L105】
- No credentials or API keys are hardcoded; TLS retrieval correctly disables hostname validation only for target flexibility.【F:reconscript/scanner.py†L232-L299】
- Rate limiting relies on sequential sleeps and manual throttling; there is no safeguard preventing users from disabling throttling entirely, contrary to README guidance.【F:reconscript/scanner.py†L138-L171】【F:README.md†L112-L117】

## Performance & Optimization Opportunities
- TCP scanning and HTTP probing run strictly sequentially; introducing async or thread pools for independent ports could reduce wall-clock time while retaining throttling controls.【F:reconscript/scanner.py†L138-L171】
- `response.text` is fully realized before truncation, which can block on large bodies; streaming reads or `iter_content` would be safer for atypical responses.【F:reconscript/scanner.py†L236-L259】
- Missing `Session.close()` prevents timely socket reuse in long-lived processes integrating ReconScript.【F:reconscript/core.py†L66-L107】

## Documentation & CI/CD Gaps
- README lacks install verification, test execution, and license sections, stopping at ethical guidance without operational follow-through.【F:README.md†L1-L129】
- Release notes capture only a bullet summary and omit upgrade guidance or dependency changes.【F:RELEASE_NOTES.md†L1-L8】
- CI attempts to cache `requirements.txt`, which is absent, causing needless cache misses and slower pipelines.【F:.github/workflows/build.yml†L22-L34】
- `docker-compose` maps `./results` but never configures `--outfile`, so operators receive no artefacts while also risking permission issues for the non-root user.【F:docker-compose.yml†L4-L11】【F:reconscript/core.py†L100-L107】

## Final Recommendations
1. Implement a real `--dry-run` flag (or remove the references) and ensure CI/container invocations align with supported CLI options.
2. Make Trivy gating by using `--exit-code 1` and surface scan results in PRs.
3. Harden HTTP probing by disabling cross-host redirects (or validating destinations) and adding per-host allowlists.
4. Close network sessions deterministically and extend tests to cover CLI flows, TCP scanning, and filesystem error handling.
5. Reconcile version metadata across code, Docker labels, and published artefacts; expand documentation to cover installation validation, licensing, and change management.

| Severity \ Likelihood | High | Medium |
| --- | --- | --- |
| **Critical** | Missing `--dry-run` flag (blocks all automated runs).【F:docker-compose.yml†L4-L11】【F:.github/workflows/build.yml†L52-L55】【F:reconscript/cli.py†L67-L134】 | – |
| **High** | Trivy scan non-blocking (vulnerabilities slip through).【F:.github/workflows/build.yml†L56-L58】 | Redirect-following HTTP probe (scope bypass).【F:reconscript/scanner.py†L236-L259】 |

Overall project integrity hinges on addressing the critical automation breakage and tightening CI security gates; once resolved, the codebase should be re-evaluated, but currently the production readiness score remains **58/100**.
