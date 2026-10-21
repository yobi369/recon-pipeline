# Recon Pipeline

**A scope-first reconnaissance toolkit for authorized security assessments.**

Recon Pipeline inventories passive Certificate Transparency observations, resolves DNS, probes HTTP(S), optionally checks a small explicit set of TCP ports, and writes reproducible JSON and Markdown reports. It is a reconnaissance tool—not a claim that observations are confirmed vulnerabilities.

> **Authorization required.** Run only against systems you own or are explicitly authorized to assess. The acknowledgement flag records operator intent; it does not verify legal permission. Respect program scope and rules of engagement.

## Quick start

Requires Python 3.10+.

```bash
python3 recon_pipeline.py example.com --authorized --output-dir results
```

Optional explicit TCP checks:

```bash
python3 recon_pipeline.py example.com --authorized --ports 22,80,443,8080 --output-dir results
```

Useful options: `--max-hosts 100`, `--workers 5` (maximum 10), `--timeout 4`, `--no-http`, and `--version`.

Outputs include `report.json`, `report.md`, and `run.log`. The report records methods, scope, timestamps, limitations, and observations. A finding is not a vulnerability verdict.

## Safety model

- Requires an explicit `--authorized` acknowledgement.
- Validates DNS domain input; rejects URLs, IP literals, and malformed names.
- Enforces root-domain and dot-delimited subdomain scope for passive discovery.
- Keeps TLS certificate verification enabled and does not follow redirects.
- Bounds concurrency, host counts, timeouts, and optional TCP ports.
- Does not construct shell commands from target input.
- Does not run exploit payloads, directory brute force, or third-party vulnerability templates.

The authorization acknowledgement is an operator safeguard, not proof of permission. DNS and Certificate Transparency data can be incomplete or stale. HTTP status and open ports are observations, not confirmed vulnerabilities.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 recon_pipeline.py --help
```

See [SECURITY.md](SECURITY.md). Licensed under Apache-2.0; see [LICENSE](LICENSE).

## Roadmap

1. Signed scope manifests and audit-friendly authorization records.
2. Pluggable passive sources with provenance and caching.
3. SARIF/HTML exports, asset deduplication, and historical diffs.
4. Optional scanner integrations behind explicit scope gates and rate limits.
