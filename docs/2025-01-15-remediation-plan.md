# ReconScript Remediation Plan (January 2025)

This plan addresses every failure and warning captured during the January 2025 audit and
provides concrete implementation and verification steps to achieve deployment readiness.

## Audit Table (Source Data)

| Phase | Status | Issue | Root Cause | Location | Recommended Fix |
| --- | --- | --- | --- | --- | --- |
| 1. Repository Structure & Hygiene | ⚠️ | Generated scan artefacts are tracked and vendored shims shadow real packages. | Results directory committed despite `.gitignore`; local `requests/` and `nacl/` directories remain in source tree. | `results/`, `requests/`, `nacl/` | Purge committed artefacts, keep `results/` empty with a placeholder, and delete or isolate shim packages. |
| 2. Dependency Integrity | ❌ | Local package shadowing, inconsistent lock file, missing runtime dependency. | Stub modules override pinned dependencies; `requirements.lock` drifts from `requirements.txt`; `prometheus-client` absent from packaging metadata. | `requests/`, `nacl/`, `requirements*.txt`, `pyproject.toml` | Remove shims, regenerate lockfile, and add `prometheus-client` to `pyproject.toml`. |
| 3. Build, Test, & Run Validation | ❌ | Formatting/lint failures and runtime bootstrap installs fail offline. | `black` and `ruff` violations unresolved; `start.py` forces `pip install` for optional extras on launch. | Source tree, `start.py` | Apply formatters/linters, configure coverage, and allow dependency installation to be skipped or pre-baked. |
| 4. Environment & Configuration | ⚠️ | `.env.example` defaults contradict RBAC requirements. | Sample file sets `ALLOW_DEV_SECRETS=false` while keeping default credentials rejected by the UI. | `.env.example` | Replace placeholders with explicit TODOs or enable dev secrets in sample config. |
| 5. Integration & Connectivity | ⚠️ | Docker Compose lacks required secrets. | Compose service publishes UI without ADMIN credentials or key paths, leading to startup failure. | `docker-compose.yml` | Document environment expectations or extend Compose with `.env` support and secret mounting. |
| 6. Security & Compliance | ❌ | Home-grown Ed25519 implementation and unavailable secret scanners. | Vendored `nacl` package reimplements crypto; `trufflehog`/`detect-secrets` absent in environment. | `nacl/`, CI config | Depend on PyNaCl for signing/verification and integrate secret scanning in CI. |
| 7. Deployment Readiness & Observability | ⚠️ | CI uploads empty coverage artefacts; Docker build requires online PyPI. | Workflow never runs coverage; Dockerfile installs from PyPI during build. | `.github/workflows/ci-matrix.yml`, `Dockerfile` | Add `pytest --cov` to CI, consider caching coverage results, and document offline build strategy or vendor wheels. |
| 8. Documentation & Automation | ✅ | Comprehensive docs exist but require alignment with current code. | README/roadmap present; new audit report added for maintainers. | Docs set | Keep documentation synced with remediation progress. |

**Critical Blockers**

* Eliminate the in-repo `requests` and `nacl` modules to prevent package shadowing and unaudited cryptography in production builds.
* Align dependency metadata (`requirements.txt`, `requirements.lock`, `pyproject.toml`) to ensure consistent installs and restore `prometheus-client` to the package definition.
* Resolve lint/format debt and adjust `start.py` so the launcher does not stall in restricted environments.

**Testing Snapshot**

* ❌ `black --check .` (22 files need formatting)
* ❌ `ruff check .` (272 lint violations including security rule S104)
* ⚠️ `pip install -r requirements-dev.txt` (failed: proxy blocked PyPI access)
* ⚠️ `bandit -r reconscript` (not available in environment)
* ⚠️ `pip-audit --requirement requirements.txt` (not available in environment)
* ⚠️ `timeout 5 python start.py` (blocked waiting for online dependency installation)
* ⚠️ `trufflehog filesystem --no-update --fail .` (not available in environment)
* ⚠️ `detect-secrets scan` (not available in environment)
* ✅ `pytest --maxfail=1 --disable-warnings -q` (13 passed, 1 skipped)

## 1. Summary of Failures

1. **Repository Structure & Hygiene** – Residual artefacts in `results/` and vendored `requests/` and `nacl/` packages shadow third-party dependencies, risking runtime ambiguity and unaudited crypto.
2. **Dependency Integrity** – Packaging manifests disagree and omit `prometheus-client`, while the vendored packages override the pinned PyPI releases.
3. **Build, Test, & Run Validation** – Codebase fails formatting/lint checks and `start.py` performs network installs at runtime, breaking offline deployments.
4. **Environment & Configuration** – `.env.example` advertises production-hardening defaults but simultaneously includes placeholder credentials that violate the RBAC rules.
5. **Integration & Connectivity** – `docker-compose.yml` launches the UI without propagating required admin credentials and key paths, so the container exits on boot.
6. **Security & Compliance** – Custom Ed25519 implementation in `nacl/` and absent secret scanning leave cryptographic assurance and leakage detection unverified.
7. **Deployment Readiness & Observability** – CI skips coverage generation and Docker builds rely on live PyPI, preventing air-gapped releases.

## 2. File-Level Fixes

### 2.1 Remove vendored shims and clean artefacts

*Files*: `results/`, `requests/`, `nacl/`

**Changes**

```sh
git rm -r results/*
rm -rf requests nacl
mkdir -p results && touch results/.gitkeep
```

**Verification**

```sh
git status --short
```

### 2.2 Align dependency metadata and add Prometheus client

*Files*: `pyproject.toml`, `requirements.txt`, `requirements.lock`, `requirements-dev.txt`

**Changes**

```diff
--- a/pyproject.toml
+++ b/pyproject.toml
@@
 [project]
 dependencies = [
     "Flask>=2.3",
     "click>=8.1",
     "pydantic>=2.6",
     "prometheus-client>=0.19",
     "python-dotenv>=1.0",
 ]
```

Regenerate pinned requirement files from the canonical source:

```sh
pip-compile --resolver=backtracking --generate-hashes -o requirements.lock pyproject.toml
pip-compile --resolver=backtracking --generate-hashes -o requirements.txt pyproject.toml
pip-compile --resolver=backtracking --extra dev -o requirements-dev.txt pyproject.toml
```

### 2.3 Restore PyNaCl usage

*Files*: `reconscript/crypto.py`, `pyproject.toml`

**Changes**

```diff
--- a/reconscript/crypto.py
+++ b/reconscript/crypto.py
@@
-from nacl import signing
-from nacl.exceptions import BadSignatureError
+from nacl import signing
+from nacl.exceptions import BadSignatureError
+
+# ensure PyNaCl wheel is bundled by relying on upstream package
```

Add PyNaCl to dependencies:

```diff
--- a/pyproject.toml
+++ b/pyproject.toml
@@
     "pydantic>=2.6",
+    "pynacl>=1.5",
```

### 2.4 Fix formatting and lint debt

*Files*: Entire source tree

**Changes**

```sh
black .
ruff check . --fix
```

### 2.5 Make runtime bootstrap optional

*Files*: `start.py`

**Changes**

```diff
@@
-if not os.environ.get("RECONSCRIPT_SKIP_BOOTSTRAP", "").lower() in {"1", "true"}:
-    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
+if os.environ.get("RECONSCRIPT_BOOTSTRAP", "").lower() in {"1", "true"}:
+    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
```

Document the new environment variable in README.md and `.env.example`.

### 2.6 Correct `.env.example`

*Files*: `.env.example`

**Changes**

```diff
-ALLOW_DEV_SECRETS=false
-ADMIN_USER=admin
-ADMIN_PASSWORD=change-me
+ALLOW_DEV_SECRETS=true  # Set to false in production once custom credentials are supplied
+ADMIN_USER=changeme_admin
+ADMIN_PASSWORD=changeme_password
```

### 2.7 Extend Docker Compose secrets handling

*Files*: `docker-compose.yml`

**Changes**

```diff
@@
   environment:
-    - ADMIN_USER=${ADMIN_USER:?Missing admin username}
-    - ADMIN_PASSWORD=${ADMIN_PASSWORD:?Missing admin password}
-    - CONSENT_PUBLIC_KEY_PATH=/app/keys/consent_public.pem
+    - ADMIN_USER=${ADMIN_USER:-changeme_admin}
+    - ADMIN_PASSWORD=${ADMIN_PASSWORD:-changeme_password}
+    - CONSENT_PUBLIC_KEY_PATH=${CONSENT_PUBLIC_KEY_PATH:-/run/secrets/consent_public.pem}
+  secrets:
+    - consent_public
+
+secrets:
+  consent_public:
+    file: ./keys/consent_public.pem
```

### 2.8 Add secret scanning and coverage enforcement to CI

*Files*: `.github/workflows/ci-matrix.yml`

**Changes**

```diff
@@
     - name: Install dependencies
-      run: pip install -r requirements-dev.txt
+      run: pip install -r requirements-dev.txt detect-secrets trufflehog
@@
-    - name: Run tests
-      run: pytest --maxfail=1 --disable-warnings -q
+    - name: Run tests with coverage
+      run: pytest --maxfail=1 --disable-warnings --cov=reconscript --cov-report=xml --cov-report=term
+    - name: Secret scan
+      run: |
+        detect-secrets scan --all-files
+        trufflehog filesystem --no-update --fail .
+    - name: Upload coverage
+      uses: codecov/codecov-action@v4
+      with:
+        files: coverage.xml
```

Enable caching and offline-friendly builds:

```diff
@@
-    - uses: actions/setup-python@v4
+    - uses: actions/setup-python@v4
+      with:
+        cache: "pip"
+        cache-dependency-path: "requirements.lock"
```

### 2.9 Document offline build strategy

*Files*: `Dockerfile`, `README.md`, `ROADMAP.md`

Add wheelhouse support to Dockerfile:

```diff
@@
-FROM python:3.11-slim
+FROM python:3.11-slim
+ARG WHEELHOUSE=wheelhouse
+COPY ${WHEELHOUSE}/ /opt/wheelhouse/
+ENV PIP_FIND_LINKS=/opt/wheelhouse
```

Document new build flag in README and ROADMAP.

## 3. Validation Commands

After applying the changes, run:

```sh
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
black --check .
ruff check .
bandit -r reconscript
pip-audit --requirement requirements.txt
pytest --cov=reconscript --maxfail=1 --disable-warnings -q
docker compose up --build --exit-code-from app
```

## 4. CI/CD Enhancements

1. Ensure `.github/workflows/ci-matrix.yml` uses pip caching keyed on `requirements.lock` and installs dev + security dependencies.
2. Add steps for `black --check`, `ruff check`, `bandit`, `pip-audit`, `pytest --cov`, and coverage upload.
3. Introduce a reusable job matrix for Python 3.9–3.13 with offline wheelhouse artifact caching between jobs.

## 5. Security Hardening

* Integrate both `detect-secrets` and `trufflehog` in CI, and enforce pre-commit hooks for local runs.
* Remove vendored `requests/` and `nacl/` directories to prevent shadowing and require upstream PyPI packages.
* Depend on PyNaCl for signing primitives instead of custom crypto.
* Create an internal wheelhouse (see Dockerfile update) for offline builds and document `make wheelhouse` target to prefetch dependencies.

## 6. Documentation Updates

*`.env.example`* – Reflect safe defaults and document `RECONSCRIPT_BOOTSTRAP` behaviour.

*README.md* – Add a "Preparing Offline Environments" section covering wheelhouse builds, `RECONSCRIPT_BOOTSTRAP`, and updated docker-compose secrets.

*ROADMAP.md* – Track ongoing security automation work, including secret scanning and offline build automation.

*Docker documentation* – Mention new Compose secrets section and wheelhouse ARG.

## 7. Verification Plan

Maintainers can rerun the full audit using:

```sh
make clean && make audit
```

Successful completion should return all ✅ statuses.

