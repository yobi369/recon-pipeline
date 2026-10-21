#!/usr/bin/env bash
# Compatibility launcher. The Python engine is the single source of scan logic.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  printf "Error: Python 3.10 or newer is required.\n" >&2
  exit 2
fi
exec python3 "$SCRIPT_DIR/recon_engine.py" "$@"
