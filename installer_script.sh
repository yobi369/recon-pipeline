#!/usr/bin/env bash
# Minimal setup: no root requirement, third-party binary downloads, or system changes.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  printf "Error: Python 3.10+ is required.\n" >&2
  exit 2
fi
"$PYTHON" - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Error: Python 3.10 or newer is required.")
print("Python", sys.version.split()[0], "is supported.")
PY
"$PYTHON" -m py_compile "$SCRIPT_DIR/recon_engine.py" "$SCRIPT_DIR/recon_pipeline.py" "$SCRIPT_DIR/recon_scope.py" "$SCRIPT_DIR/recon_compare.py" "$SCRIPT_DIR/recon_verify.py"
printf "\nSetup verified. No external packages are required.\n"
printf "Run: python3 %s/recon_engine.py example.com --authorized\n" "$SCRIPT_DIR"
printf "For scoped engagements, copy and edit scope.example.json, then pass --scope-file.\n"
printf "Only use --authorized for a target you have permission to assess.\n"
