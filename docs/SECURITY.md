# Security Overview
This project is designed for safe, educational, and authorized use only.

- No exploitation or fuzzing.
- Read-only reconnaissance and metadata collection.
- Sanitized logging with consent manifest tracking.

## Responsible Disclosure
Report findings respectfully by opening a private issue or contacting the maintainer listed in the README.

## Hardening Checklist
- Generate production-only keys and set the following environment variables before starting any service:
  - `FLASK_SECRET_KEY_FILE` → path to a randomly generated 32-byte secret.
  - `ADMIN_USER` / `ADMIN_PASSWORD` → non-default credentials (password ≥ 12 characters).
  - `CONSENT_PUBLIC_KEY_PATH` → consent verification key.
  - `REPORT_SIGNING_KEY_PATH` → report signing key used by `--sign-report` or UI downloads.
- Leave `ALLOW_DEV_SECRETS` unset (default) in production; setting it to `true` is only for ephemeral demos that explicitly use the sample keys shipped under `keys/`.
- Run scans only against systems where you have explicit written permission.
- Keep dependencies updated using `requirements.lock` or `pyproject.toml` and run `pip-audit`/`bandit` regularly.
- Enable HTTPS termination, reverse-proxy authentication, and network segmentation before exposing the UI publicly.
- Scrape `/metrics` with your monitoring stack and alert on abnormal `recon_scans_total{status!="completed"}` increases.

## Secret Rotation
- Rotate UI credentials and signing keys at least every 90 days or immediately after personnel changes.
- Store keys in a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault) and mount them into the container as read-only files.
- After rotating keys, restart the web UI or CLI sessions so the new files are loaded.
