#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

RESULTS_DIR="${RESULTS_DIR:-results}"
KEYS_DIR="${KEYS_DIR:-keys}"
mkdir -p "$RESULTS_DIR"
mkdir -p "$KEYS_DIR"

DEV_PRIV="$KEYS_DIR/dev_ed25519.priv"
DEV_PUB="$KEYS_DIR/dev_ed25519.pub"
DEV_FLASK="$KEYS_DIR/dev_flask_secret.key"

if [[ ! -f "$DEV_PRIV" || ! -f "$DEV_PUB" ]]; then
  python3 - "$DEV_PRIV" "$DEV_PUB" <<'PY'
import base64
import os
import sys
from pathlib import Path

from nacl.signing import SigningKey

priv_path = Path(sys.argv[1])
pub_path = Path(sys.argv[2])

seed = os.urandom(32)
signing_key = SigningKey(seed)

priv_path.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="utf-8")
pub_path.write_text(
    base64.b64encode(bytes(signing_key.verify_key)).decode("ascii") + "\n", encoding="utf-8"
)
PY
  echo "[dev] Generated placeholder ed25519 keypair in $KEYS_DIR (replace for production)."
fi

if [[ ! -f "$DEV_FLASK" ]]; then
  echo "development-secret-key-change-me" > "$DEV_FLASK"
  echo "[dev] Created default Flask secret key. Replace before deploying."
fi

echo "🚀 Launching ReconScript via start.py"
PYTHON_BIN=${PYTHON:-python3}
"$PYTHON_BIN" start.py "$@"
