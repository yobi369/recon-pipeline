# Recon Pipeline

**A scope-first reconnaissance toolkit for authorized security assessments.**

Recon Pipeline discovers passive Certificate Transparency observations, resolves DNS, probes HTTP(S), optionally checks a small explicit set of TCP ports, and produces JSON and Markdown evidence reports. These are reconnaissance observations, not confirmed vulnerability findings.

> **Authorization required.** Run only against assets you own or have explicit permission to assess. The acknowledgement flag does not independently verify permission. Respect written scope and rules of engagement.

## Quick start

Requires Python 3.10+. The core uses only the Python standard library.

```bash
python3 recon_engine.py example.com --authorized --output-dir results
```

Compatibility launchers are also available:

```bash
python3 recon_pipeline.py example.com --authorized
bash recon_pipeline.sh example.com --authorized
```

Optional explicit TCP checks:

```bash
python3 recon_engine.py example.com --authorized --ports 22,80,443,8080 --output-dir results
```

Options include `--max-hosts 100`, `--workers 5` (maximum 10), `--timeout 4`, `--no-http`, and `--version`. Outputs: `report.json`, `report.md`, `run.log`, and `manifest.json` (artifact integrity hashes). Reports record collection configuration, source provenance, start/end times, and elapsed duration.

## Time-bounded engagement scope

For a real engagement, create a scope manifest from `scope.example.json`, replace the example engagement and authorization reference, set an expiry time, and list only assets covered by written permission. The engine refuses an expired manifest and requires the command-line `--authorized` acknowledgement as a second operator check.

```bash
python3 recon_engine.py example.com --authorized --scope-file scope.example.json --output-dir results
```

When `allowed_hosts` is non-empty, each listed name is allowed; subdomains are included for non-root entries, while listing `root_domain` permits only the root itself. `excluded_hosts` excludes each listed name and its subdomains. Every manifest hostname must fall within `root_domain`; the report records the scope-manifest SHA-256 and authorization reference. This is an enforcement aid, not independent verification of the underlying permission.

## Historical evidence comparison

Recon Pipeline can compare two saved JSON reports from the same root-domain scope. This helps teams identify observed inventory, DNS, HTTP-status, and explicitly tested TCP-state changes over time without presenting ordinary changes as vulnerability findings.

```bash
# Capture each authorized run into a separate directory.
python3 recon_engine.py example.com --authorized --output-dir runs/2026-10-20
python3 recon_engine.py example.com --authorized --output-dir runs/2026-10-21

# Compare the baseline and later observation.
python3 recon_compare.py runs/2026-10-20/report.json runs/2026-10-21/report.json --output-dir comparison
```

The comparison writes `comparison.json` and `comparison.md`. It records SHA-256 hashes of the exact input report bytes so a reviewer can identify which evidence files were compared. Every reconnaissance run also writes `manifest.json`, containing byte counts and SHA-256 hashes for its JSON, Markdown, and log artifacts. Verify those files with `python3 recon_verify.py runs/2026-10-21/manifest.json`. This detects accidental or post-collection changes relative to the manifest; it is not a digital signature or proof of who created the report. Host absence is described as "not observed", not proof that an asset was removed. Reports with collection errors are flagged as incomplete. Compare runs collected with equivalent scope and configuration.

## Safety model

- Validates domain input; rejects URLs and IP literals.
- Applies dot-delimited root-domain scope checks to discovered hostnames.
- TLS certificate verification remains enabled; redirects are not followed.
- Concurrency, host counts, timeouts, and optional TCP ports are bounded.
- Does not construct shell commands from target input.
- No exploit payloads, directory brute force, or third-party vulnerability-template scans.
- The authorization acknowledgement is not proof of permission.
- CT/DNS results may be incomplete or stale; HTTP status and open ports do not confirm vulnerabilities.

## Setup and tests

```bash
bash installer_script.sh
python3 -m unittest discover -s tests -v
```

The installer performs local version and syntax checks only. It does not run as root, install third-party scanners, or download binaries.

See [SECURITY.md](SECURITY.md). Licensed under Apache-2.0; see [LICENSE](LICENSE).
