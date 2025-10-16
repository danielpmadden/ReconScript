@echo off
setlocal
cd /d %~dp0

echo Launching ReconScript...
if not exist results mkdir results

docker build -t reconscript .
docker run --rm -p 5000:5000 -v "%cd%\results:/app/results" reconscript | tee results\latest.log

pause
