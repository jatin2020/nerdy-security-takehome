#!/usr/bin/env bash
set -e

# Change directory to repository root
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "================================================================="
echo "Running Security Triage Service End-to-End Walkthrough"
echo "================================================================="

if [ -f ".venv/bin/python" ]; then
    .venv/bin/python scripts/run_demo.py
else
    python3 scripts/run_demo.py
fi
