# ReconScript Demo Checklist

1. **CLI HTML run**
   ```bash
   python3 -m venv .venv && source .venv/bin/activate
   pip install --no-deps .[dev]
   python -m reconscript --target 127.0.0.1 --ports 3000
   ```
   - Expect `results/127-0-0-1-*.html` to open automatically in the default browser.

2. **Web UI walk-through**
   ```bash
   python web_ui.py
   ```
   - Browse to http://127.0.0.1:5000/
   - Submit target `127.0.0.1` and ports `3000`.
   - Wait for completion and open the HTML link provided.

3. **Docker Compose pairing with Juice Shop**
   ```bash
   docker-compose up
   ```
   - Juice Shop available on http://127.0.0.1:3000/
   - ReconScript UI available on http://127.0.0.1:5000/
   - Reports persist to `./results/` on the host.

4. **Optional PDF verification**
   ```bash
   docker build --build-arg INCLUDE_PDF=true -t reconscript:pdf .
   ```
   - Run the image to confirm PDF generation succeeds when dependencies are bundled.
