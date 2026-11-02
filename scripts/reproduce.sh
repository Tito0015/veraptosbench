#!/usr/bin/env bash
# Offline checks for the frozen benchmark. No GitHub, OpenRouter, or scanner calls.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${1:-}" != "--verify-all" ]]; then
  echo "usage: bash scripts/reproduce.sh --verify-all" >&2
  exit 2
fi
if command -v python >/dev/null 2>&1; then
  PY=python
elif command -v python.exe >/dev/null 2>&1; then
  PY=python.exe
elif command -v python3 >/dev/null 2>&1; then
  PY=python3
else
  echo "python not found" >&2
  exit 1
fi
"$PY" scripts/hash_heldout.py --check
"$PY" scripts/determinism_check.py
"$PY" scripts/mutator.py --self-check
echo "reproduce ok"
