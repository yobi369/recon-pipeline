#!/usr/bin/env python3
"""Compare two Recon Pipeline evidence reports without treating deltas as vulnerabilities."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import recon_engine


def load_report(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        report = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: invalid JSON report") from exc
    if not isinstance(report, dict) or report.get("schema_version") != "1.0":
        raise ValueError(f"{path}: unsupported or missing report schema_version")
    if report.get("tool") != "Recon Pipeline":
        raise ValueError(f"{path}: report was not produced by Recon Pipeline")
    scope = report.get("scope")
    if not isinstance(scope, dict) or not isinstance(scope.get("root_domain"), str):
        raise ValueError(f"{path}: missing root domain scope")
    try:
        root = recon_engine.normalize_domain(scope["root_domain"])
    except ValueError as exc:
        raise ValueError(f"{path}: invalid root domain scope") from exc
    if root != scope["root_domain"]:
        raise ValueError(f"{path}: root domain must be normalized")
    hosts = report.get("hosts")
    if not isinstance(hosts, list):
        raise ValueError(f"{path}: hosts must be a list")
    seen: set[str] = set()
    for item in hosts:
        if not isinstance(item, dict) or not isinstance(item.get("host"), str):
            raise ValueError(f"{path}: every host observation must contain a host")
        host = recon_engine.normalize_domain(item["host"])
        if not recon_engine.in_scope(host, root):
            raise ValueError(f"{path}: out-of-scope host in report: {host}")
        if host in seen:
            raise ValueError(f"{path}: duplicate host observation: {host}")
        seen.add(host)
        addresses = item.get("addresses", [])
        if not isinstance(addresses, list) or any(not isinstance(x, str) for x in addresses):
            raise ValueError(f"{path}: addresses must be a list of strings")
        http = item.get("http", [])
        if not isinstance(http, list):
            raise ValueError(f"{path}: http observations must be a list")
        for probe in http:
            if not isinstance(probe, dict) or not isinstance(probe.get("url"), str):
                raise ValueError(f"{path}: malformed HTTP observation")
            status = probe.get("status")
            if status is not None and (not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599):
                raise ValueError(f"{path}: invalid HTTP status for {host}")
    ports = report.get("tcp_observations", [])
    if not isinstance(ports, list):
        raise ValueError(f"{path}: tcp_observations must be a list")
    for item in ports:
        if not isinstance(item, dict) or not isinstance(item.get("host"), str):
            raise ValueError(f"{path}: malformed TCP observation")
        host = recon_engine.normalize_domain(item["host"])
        port = item.get("port")
        if not recon_engine.in_scope(host, root) or not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError(f"{path}: invalid or out-of-scope TCP observation")
    summary = report.get("summary", {})
    if not isinstance(summary, dict) or not isinstance(summary.get("errors", 0), int):
        raise ValueError(f"{path}: malformed summary")
    return report, digest


def _http_map(host: dict[str, Any]) -> dict[str, int | None]:
    return {item["url"]: item.get("status") for item in host.get("http", [])}


def compare_reports(baseline: dict[str, Any], current: dict[str, Any],
                    baseline_sha256: str, current_sha256: str) -> dict[str, Any]:
    base_root = baseline["scope"]["root_domain"]
    current_root = current["scope"]["root_domain"]
    if base_root != current_root:
        raise ValueError("reports have different root-domain scopes")

    before = {item["host"]: item for item in baseline["hosts"]}
    after = {item["host"]: item for item in current["hosts"]}
    changes: list[dict[str, Any]] = []

    for host in sorted(after.keys() - before.keys()):
        changes.append({"category": "host_first_observed", "subject": host,
                        "before": None, "after": "observed",
                        "interpretation": "Host appears in the current observation set; this does not prove it was newly created."})
    for host in sorted(before.keys() - after.keys()):
        changes.append({"category": "host_not_observed", "subject": host,
                        "before": "observed", "after": None,
                        "interpretation": "Host was not present in the current observation set; DNS, CT, network, or collection differences may explain this."})

    for host in sorted(before.keys() & after.keys()):
        b, c = before[host], after[host]
        b_addrs, c_addrs = set(b.get("addresses", [])), set(c.get("addresses", []))
        if b_addrs != c_addrs:
            changes.append({"category": "dns_address_set_changed", "subject": host,
                            "before": sorted(b_addrs), "after": sorted(c_addrs),
                            "interpretation": "Resolved address set changed between observations."})
        b_http, c_http = _http_map(b), _http_map(c)
        for url in sorted(b_http.keys() | c_http.keys()):
            if url not in b_http or url not in c_http or b_http[url] != c_http[url]:
                changes.append({"category": "http_observation_changed", "subject": url,
                                "before": b_http.get(url), "after": c_http.get(url),
                                "interpretation": "HTTP observation appeared, disappeared, or changed status; this is not a vulnerability finding."})

    def open_ports(report: dict[str, Any]) -> dict[tuple[str, int], str]:
        return {(item["host"], item["port"]): item.get("state", "unknown")
                for item in report.get("tcp_observations", [])}

    b_ports, c_ports = open_ports(baseline), open_ports(current)
    for key in sorted(b_ports.keys() | c_ports.keys()):
        b_state, c_state = b_ports.get(key), c_ports.get(key)
        if b_state != c_state:
            changes.append({"category": "tcp_observation_changed",
                            "subject": f"{key[0]}:{key[1]}", "before": b_state, "after": c_state,
                            "interpretation": "TCP state observation changed; reachability is not proof of service identity or vulnerability."})

    incomplete = bool(baseline.get("errors") or current.get("errors")
                      or baseline.get("summary", {}).get("errors", 0)
                      or current.get("summary", {}).get("errors", 0))
    if incomplete:
        caveat = "At least one report recorded collection errors; absence-based changes are especially uncertain."
    else:
        caveat = "No collection errors were recorded, but passive discovery and network observations can still be incomplete."
    return {
        "schema_version": "1.0",
        "tool": "Recon Pipeline Comparison",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "scope": {"root_domain": base_root},
        "baseline": {"run_id": baseline.get("run_id"), "completed_at": baseline.get("completed_at"),
                     "sha256": baseline_sha256},
        "current": {"run_id": current.get("run_id"), "completed_at": current.get("completed_at"),
                    "sha256": current_sha256},
        "summary": {"baseline_hosts": len(before), "current_hosts": len(after),
                    "changes_observed": len(changes), "collection_incomplete": incomplete},
        "changes": changes,
        "caveats": [caveat, "Changes describe differences between observations, not confirmed asset creation, removal, exposure, or vulnerabilities.",
                    "Compare only reports collected under comparable authorization, scope, methods, and configuration."]
    }


def render_markdown(result: dict[str, Any]) -> str:
    lines = [f"# Recon Pipeline Comparison: {result['scope']['root_domain']}", "",
             f"- Created UTC: {result['created_at']}",
             f"- Baseline run: {result['baseline'].get('run_id') or 'unknown'}",
             f"- Current run: {result['current'].get('run_id') or 'unknown'}", "",
             "## Summary", ""]
    lines.extend(f"- {key.replace('_', ' ').title()}: {value}"
                 for key, value in result["summary"].items())
    lines += ["", "## Observed changes", ""]
    if result["changes"]:
        lines += ["| Category | Subject | Before | After |", "|---|---|---|---|"]
        for change in result["changes"]:
            before = json.dumps(change["before"], ensure_ascii=False)
            after = json.dumps(change["after"], ensure_ascii=False)
            safe = lambda value: str(value).replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {safe(change['category'])} | {safe(change['subject'])} | {safe(before)} | {safe(after)} |")
        lines += ["", "### Interpretation", ""]
        lines.extend(f"- **{change['category']} — {change['subject']}:** {change['interpretation']}"
                     for change in result["changes"])
    else:
        lines.append("No differences were detected in the supported observation fields.")
    lines += ["", "## Caveats", ""]
    lines.extend(f"- {item}" for item in result["caveats"])
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare two Recon Pipeline JSON reports; deltas are observations, not vulnerability claims.")
    parser.add_argument("baseline", type=Path, help="earlier report.json")
    parser.add_argument("current", type=Path, help="later report.json")
    parser.add_argument("--output-dir", type=Path, default=Path("recon_comparison"))
    args = parser.parse_args(argv)
    try:
        baseline, baseline_hash = load_report(args.baseline)
        current, current_hash = load_report(args.current)
        result = compare_reports(baseline, current, baseline_hash, current_hash)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "comparison.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (args.output_dir / "comparison.md").write_text(render_markdown(result), encoding="utf-8")
        print(f"Comparison written to {args.output_dir}")
        print(json.dumps(result["summary"], indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
