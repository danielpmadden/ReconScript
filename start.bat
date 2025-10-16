@echo off
setlocal
cd /d %~dp0

if not exist results mkdir results
set "LOGFILE=results\latest.log"
set "PYTHON_BIN=%PYTHON%"
if "%PYTHON_BIN%"=="" set "PYTHON_BIN=python"

echo Launching ReconScript via start.py...
echo Logs mirror to %LOGFILE%

"%PYTHON_BIN%" start.py %*

pause
