@echo off
setlocal enabledelayedexpansion
pushd %~dp0

set "RESULTS_DIR=%RESULTS_DIR:%=%"
if "%RESULTS_DIR%"=="" set "RESULTS_DIR=results"

if not exist "%RESULTS_DIR%" mkdir "%RESULTS_DIR%"

echo 🚀 Launching ReconScript via start.py
set "PYTHON_BIN=%PYTHON%"
if "%PYTHON_BIN%"=="" set "PYTHON_BIN=python"
%PYTHON_BIN% start.py %*

popd
