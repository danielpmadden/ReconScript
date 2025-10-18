# HELP.md

## Getting Started
1. Clone the repository: `git clone https://github.com/YOUR_GITHUB_USERNAME/ReconScript.git`.
2. Change into the project directory: `cd ReconScript`.
3. Choose a launch option:
   - `./start.sh` on Linux or macOS.
   - `start.bat` on Windows.
   - `docker compose up` when Docker is available.

## Configuration Tips
- Copy `.env.example` to `.env` to override defaults.
- Review the `keys/` directory and replace development keys before production usage.
- Use `requirements.txt` for runtime installs and `requirements-dev.txt` for local development tooling.

## Troubleshooting
- **Web UI not loading:** confirm port 5000 is free and that the Flask service finished booting.
- **Missing dependencies:** run `python install_dependencies.py` or `pip install -r requirements.txt` inside a virtual environment.
- **Permission errors on results:** ensure the `results/` directory is writable by the process running the scan.
- **Docker volume issues:** remove the container with `docker compose down -v` and start fresh.

## Useful Commands
- `pytest` — run automated tests.
- `bandit -r reconscript` — static analysis for obvious security pitfalls.
- `black .` and `flake8` — formatting and linting (non-blocking).

## Need More?
Consult the README for architecture, workflows, and contact details.
