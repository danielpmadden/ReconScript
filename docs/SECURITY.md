# Security Overview
This project is designed for safe, educational, and authorized use only.

- No exploitation or fuzzing.
- Read-only reconnaissance and metadata collection.
- Sanitized logging with consent manifest tracking.

## Responsible Disclosure
Report findings respectfully by opening a private issue or contacting the maintainer listed in the README.

## Hardening Checklist
- Replace development keys in `keys/` with environment-specific credentials.
- Run scans only against systems where you have explicit written permission.
- Keep dependencies updated using `requirements.lock` or `pyproject.toml`.
- Enable HTTPS termination and authentication before exposing the UI publicly.
