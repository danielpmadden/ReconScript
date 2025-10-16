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
import binascii
import sys
priv_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
pub_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
with open(sys.argv[1], "wb") as priv_file:
    priv_file.write(binascii.unhexlify(priv_hex))
with open(sys.argv[2], "wb") as pub_file:
    pub_file.write(binascii.unhexlify(pub_hex))
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
