# Recon Pipeline

**A scope-first reconnaissance toolkit for authorized security assessments.**

The new modular engine inventories passive Certificate Transparency observations, resolves DNS, probes HTTP(S), optionally checks a small explicit set of TCP ports, and writes reproducible JSON and Markdown reports. These are reconnaissance observations, not confirmed vulnerability findings.

> **Authorization required.** Run only against assets you own or have explicit permission to assess. The acknowledgement flag does not independently verify permission. Respect written scope and rules of engagement.

## Quick start
Requires Python 3.10+.

```bash
python3 recon_engine.py example.com --authorized --output-dir results
```

Optional explicit TCP checks:

```bash
python3 recon_engine.py example.com --authorized --ports 22,80,443,8080 --output-dir results
```

Options include `--max-hosts 100`, `--workers 5` (maximum 10), `--timeout 4`, `--no-http`, and `--version`. Outputs: `report.json`, `report.md`, and `run.log`.

## Safety and limitations
- Validates domain input; rejects URLs and IP literals.
- Applies dot-delimited subdomain scope checks.
- TLS certificate verification remains enabled; redirects are not followed.
- Concurrency, host counts, timeouts, and optional TCP ports are bounded.
- No target-derived shell commands, exploit payloads, directory brute force, or vulnerability-template scans.
- Authorization acknowledgement is not proof of permission.
- CT/DNS results may be incomplete or stale; HTTP status and open ports do not confirm vulnerabilities.

## Development
```bash
python3 -m unittest discover -s tests -v
python3 recon_engine.py --help
```

The original `recon_pipeline.py` and shell scripts are retained for reference and have not yet been fully migrated to the safer engine. Prefer `recon_engine.py` for new use until the legacy scripts are retired or hardened.

See [SECURITY.md](SECURITY.md). Licensed under Apache-2.0; see [LICENSE](LICENSE).
