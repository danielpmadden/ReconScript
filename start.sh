#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

LOG_DIR="results"
LOG_FILE="$LOG_DIR/latest.log"
mkdir -p "$LOG_DIR"

echo "🚀 Launching ReconScript via start.py"
echo "ℹ️  Live logs mirror to $LOG_FILE"

PYTHON_BIN=${PYTHON:-python3}

"$PYTHON_BIN" start.py "$@"
