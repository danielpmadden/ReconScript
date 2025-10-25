#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

RESULTS_DIR="${RESULTS_DIR:-results}"
mkdir -p "$RESULTS_DIR"

echo "🚀 Launching ReconScript via start.py"
PYTHON_BIN=${PYTHON:-python3}
"$PYTHON_BIN" start.py "$@"
