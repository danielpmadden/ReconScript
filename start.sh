#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "🚀 Launching ReconScript..."
mkdir -p results

docker build -t reconscript .
docker run --rm -p 5000:5000 -v "$(pwd)/results:/app/results" reconscript | tee results/latest.log
