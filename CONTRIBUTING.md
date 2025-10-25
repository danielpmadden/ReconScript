# Contributing to ReconScript

Thank you for helping keep ReconScript safe, scoped, and respectful of consent.

## Ground rules

- Only contribute features that preserve read-only reconnaissance. Never add intrusive or destructive functionality.
- All scans must remain single-target by default. CIDR support is opt-in via `ALLOW_CIDR=true`.
- Non-local targets require a signed scope manifest and consent verification. Never ship production keys in the repository.
- Evidence level defaults to `low`. `high` evidence must remain explicitly gated behind signed consent.
- Do not expose the Flask UI publicly unless `ENABLE_PUBLIC_UI=true` **and** `ENABLE_RBAC=true` are set. The UI warns when public mode is active.

## Development workflow

1. Create and activate a Python 3.11 virtual environment.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   ```
3. Copy `.env.example` to `.env` and adjust values as needed.
4. Run formatting and linting before pushing:
   ```bash
   black .
   ruff check .
   ```
5. Execute unit tests:
   ```bash
   pytest -m "not integration"
   ```
6. Integration tests are optional and rely on explicit opt-in:
   ```bash
   INTEGRATION=true INTEGRATION_SCANME=true pytest -m integration
   ```

## Submitting changes

- Every pull request must include an entry in `results/index.json` only through the automated report writing; never edit index files manually.
- Include updates to documentation when you add or change functionality, especially around consent workflows.
- Sign off commits according to the DCO in `DCO.txt`.
- New features must include relevant unit tests and, when applicable, integration tests guarded by the `integration` marker.

