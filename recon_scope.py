#!/usr/bin/env python3
"""Time-bounded, explicit engagement scope manifests for Recon Pipeline."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import recon_engine


def load_scope(path: Path, target: str, now: datetime | None = None) -> dict[str, Any]:
    raw = path.read_bytes()
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("scope file must be valid UTF-8 JSON") from exc
    if not isinstance(data, dict) or data.get("schema_version") != "1.0":
        raise ValueError("scope file must contain schema_version 1.0")
    engagement_id = data.get("engagement_id")
    if not isinstance(engagement_id, str) or not engagement_id.strip() or len(engagement_id) > 128:
        raise ValueError("scope file requires a non-empty engagement_id (max 128 characters)")
    if not isinstance(data.get("root_domain"), str):
        raise ValueError("scope file requires a root_domain string")
    root = recon_engine.normalize_domain(data["root_domain"])
    if recon_engine.normalize_domain(target) != root:
        raise ValueError("target must match root_domain in the scope file")
    authorization_reference = data.get("authorization_reference")
    if not isinstance(authorization_reference, str) or not authorization_reference.strip() or len(authorization_reference) > 256:
        raise ValueError("scope file requires an authorization_reference (max 256 characters)")
    expires_raw = data.get("expires_at")
    if not isinstance(expires_raw, str):
        raise ValueError("scope file requires an expires_at timestamp with timezone")
    try:
        expires = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("expires_at must be ISO 8601 with timezone") from exc
    if expires.tzinfo is None or expires.utcoffset() is None:
        raise ValueError("expires_at must include a timezone")
    current_time = now or datetime.now(timezone.utc)
    if expires <= current_time:
        raise ValueError("scope authorization has expired")
    allowed = _domain_list(data.get("allowed_hosts", []), root, "allowed_hosts")
    excluded = _domain_list(data.get("excluded_hosts", []), root, "excluded_hosts")
    if set(allowed) & set(excluded):
        raise ValueError("a hostname cannot be both allowed and excluded")
    return {
        "root_domain": root,
        "engagement_id": engagement_id.strip(),
        "authorization_reference": authorization_reference.strip(),
        "expires_at": expires.astimezone(timezone.utc).isoformat(),
        "allowed_hosts": sorted(set(allowed)),
        "excluded_hosts": sorted(set(excluded)),
        "scope_file_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _domain_list(value: Any, root: str, field: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list of DNS domains")
    result = []
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{field} must contain only DNS domain strings")
        domain = recon_engine.normalize_domain(item)
        if not recon_engine.in_scope(domain, root):
            raise ValueError(f"{field} contains a hostname outside root_domain: {domain}")
        result.append(domain)
    return result


def host_is_in_scope(host: str, scope: dict[str, Any]) -> bool:
    root = scope["root_domain"]
    if not recon_engine.in_scope(host, root):
        return False
    if any(host == excluded or host.endswith("." + excluded)
           for excluded in scope.get("excluded_hosts", [])):
        return False
    allowed = scope.get("allowed_hosts", [])
    if allowed and not any(host == item or host.endswith("." + item) for item in allowed):
        return False
    return True
