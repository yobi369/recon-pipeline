#!/usr/bin/env python3
"""Verify the SHA-256 and size records in a Recon Pipeline artifact manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def verify_manifest(path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read valid manifest: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("manifest_schema_version") != "1.0":
        raise ValueError("unsupported or missing manifest schema version")
    if manifest.get("tool") != "Recon Pipeline":
        raise ValueError("manifest is not from Recon Pipeline")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError("manifest artifacts must be a non-empty list")
    root = path.resolve().parent
    seen: set[str] = set()
    checked = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("malformed artifact entry")
        relative = artifact.get("path")
        expected_hash = artifact.get("sha256")
        expected_size = artifact.get("bytes")
        if not isinstance(relative, str) or Path(relative).name != relative or relative in ("", ".", "..", path.name):
            raise ValueError(f"unsafe artifact path: {relative!r}")
        if relative in seen:
            raise ValueError(f"duplicate artifact path: {relative}")
        seen.add(relative)
        if not isinstance(expected_hash, str) or len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash):
            raise ValueError(f"invalid SHA-256 digest for {relative}")
        if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
            raise ValueError(f"invalid byte count for {relative}")
        file_path = root / relative
        if file_path.resolve().parent != root or not file_path.is_file():
            raise ValueError(f"artifact missing or not a regular file: {relative}")
        raw = file_path.read_bytes()
        actual_hash = hashlib.sha256(raw).hexdigest()
        if len(raw) != expected_size or actual_hash != expected_hash:
            raise ValueError(f"integrity check failed: {relative}")
        checked.append({"path": relative, "bytes": len(raw), "sha256": actual_hash, "status": "verified"})
    return {"manifest": str(path), "status": "verified", "artifacts_verified": len(checked), "artifacts": checked}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a Recon Pipeline manifest against its report artifacts.")
    parser.add_argument("manifest", type=Path, help="manifest.json generated with a reconnaissance run")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(verify_manifest(args.manifest), indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
