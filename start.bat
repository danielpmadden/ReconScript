@echo off
setlocal enabledelayedexpansion
pushd %~dp0

set "RESULTS_DIR=%RESULTS_DIR:%=%"
if "%RESULTS_DIR%"=="" set "RESULTS_DIR=results"
set "KEYS_DIR=%KEYS_DIR:%=%"
if "%KEYS_DIR%"=="" set "KEYS_DIR=keys"

if not exist "%RESULTS_DIR%" mkdir "%RESULTS_DIR%"
if not exist "%KEYS_DIR%" mkdir "%KEYS_DIR%"

set "DEV_PRIV=%KEYS_DIR%\dev_ed25519.priv"
set "DEV_PUB=%KEYS_DIR%\dev_ed25519.pub"
set "DEV_FLASK=%KEYS_DIR%\dev_flask_secret.key"

if not exist "%DEV_PRIV%" (
  python - <<PY %DEV_PRIV% %DEV_PUB%
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
  echo [dev] Generated placeholder ed25519 keypair in %KEYS_DIR% (replace for production).
)

if not exist "%DEV_FLASK%" (
  echo development-secret-key-change-me>"%DEV_FLASK%"
  echo [dev] Created default Flask secret key. Replace before deploying.
)

echo 🚀 Launching ReconScript via start.py
set "PYTHON_BIN=%PYTHON%"
if "%PYTHON_BIN%"=="" set "PYTHON_BIN=python"
%PYTHON_BIN% start.py %*

popd
