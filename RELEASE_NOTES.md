# ReconScript v0.2.0 Release Notes

## Highlights
- Rebuilt the project as a modular package with dedicated CLI, orchestration, and scanning layers to improve maintainability and reuse while keeping the `python -m reconscript` entry point.
- Hardened the command-line interface with unified argument parsing, strict validation, configurable timeouts/throttling, and structured logging controls for verbose or quiet operation.
- Enhanced network safety and resiliency through IP address validation, optional IPv6 resolution, TCP throttling, HTTP retry/backoff handling, and TLS/robots collection guarded by focused exception handling.
- Added robust cookie flag extraction, security header evaluation, and automated finding generation to surface meaningful observations in the JSON report.
- Updated documentation, sample output, and tests to guide ethical usage and provide coverage for helper utilities.
