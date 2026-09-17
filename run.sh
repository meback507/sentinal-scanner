#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "============================================================"
echo " AegisSec Platform - Unified SAST & SCA Security Engine     "
echo "============================================================"

# Check if .venv exists
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv --without-pip
    curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    .venv/bin/python3 /tmp/get-pip.py
    rm -f /tmp/get-pip.py
    echo "[*] Installing dependencies..."
    .venv/bin/pip install -r requirements.txt
fi

echo "[*] Starting AegisSec on http://127.0.0.1:8000 ..."
exec .venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
