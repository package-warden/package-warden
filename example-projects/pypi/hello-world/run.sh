#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip cache purge
pip install --verbose \
  --index-url http://localhost:5050/v1/proxy/pypi/simple/ \
  --trusted-host localhost \
  -r requirements.txt \
  --force-reinstall
python main.py
