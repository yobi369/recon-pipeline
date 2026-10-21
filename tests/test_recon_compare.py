import json
import tempfile
import unittest
from pathlib import Path

import recon_compare


def report(hosts=None, ports=None, errors=None, run_id="run"):
    hosts = hosts if hosts is not None else [
        {"host": "example.com", "addresses": ["192.0.2.1"], "http": [{"url": "https://example.com/", "status": 200}]}
    ]
    return {
        "schema_version": "1.0",
        "tool": "Recon Pipeline",
        "run_id": run_id,
        "completed_at": "2026-10-21T00:00:00+00:00",
        "scope": {"root_domain": "example.com"},
        "summary": {"errors": len(errors or [])},
        "hosts": hosts,
        "tcp_observations": ports or [],
        "errors": errors or [],
    }


class CompareTests(unittest.TestCase):
    def test_detects_dns_http_tcp_and_host_deltas(self):
        baseline = report(
            hosts=[
                {"host": "example.com", "addresses": ["192.0.2.1"], "http": [{"url": "https://example.com/", "status": 200}]},
                {"host": "old.example.com", "addresses": ["192.0.2.2"], "http": []},
            ],
            ports=[{"host": "example.com", "port": 443, "state": "open"}],
            run_id="baseline",
        )
        current = report(
            hosts=[
                {"host": "example.com", "addresses": ["192.0.2.9"], "http": [{"url": "https://example.com/", "status": 503}]},
                {"host": "new.example.com", "addresses": ["192.0.2.3"], "http": []},
            ],
            ports=[{"host": "example.com", "port": 443, "state": "not_confirmed_open"}],
            run_id="current",
        )
        result = recon_compare.compare_reports(baseline, current, "a" * 64, "b" * 64)
        categories = {item["category"] for item in result["changes"]}
        self.assertEqual(result["summary"]["changes_observed"], 5)
        self.assertTrue({
            "host_first_observed", "host_not_observed", "dns_address_set_changed",
            "http_observation_changed", "tcp_observation_changed"
        }.issubset(categories))
        self.assertEqual(result["baseline"]["sha256"], "a" * 64)
        self.assertTrue(any("not vulnerability" in c for c in result["caveats"]))

    def test_no_deltas_for_equal_observations(self):
        one = report()
        result = recon_compare.compare_reports(one, one, "a" * 64, "a" * 64)
        self.assertEqual(result["changes"], [])
        self.assertEqual(result["summary"]["changes_observed"], 0)

    def test_rejects_different_scope(self):
        one = report()
        other = report()
        other["scope"]["root_domain"] = "other.example"
        with self.assertRaisesRegex(ValueError, "different root-domain scopes"):
            recon_compare.compare_reports(one, other, "a", "b")

    def test_rejects_out_of_scope_host_in_input_file(self):
        invalid = report(hosts=[
            {"host": "example.com.attacker.test", "addresses": [], "http": []}
        ])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "out-of-scope host"):
                recon_compare.load_report(path)

    def test_load_report_records_sha256_of_exact_bytes(self):
        data = report()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            raw = json.dumps(data, sort_keys=True).encode()
            path.write_bytes(raw)
            loaded, digest = recon_compare.load_report(path)
            import hashlib
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
            self.assertEqual(loaded["scope"]["root_domain"], "example.com")

    def test_cli_writes_json_and_markdown(self):
        one = report()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "baseline.json"
            current = Path(directory) / "current.json"
            output = Path(directory) / "output"
            base.write_text(json.dumps(one), encoding="utf-8")
            current.write_text(json.dumps(one), encoding="utf-8")
            self.assertEqual(recon_compare.main([str(base), str(current), "--output-dir", str(output)]), 0)
            self.assertEqual(json.loads((output / "comparison.json").read_text())["summary"]["changes_observed"], 0)
            self.assertIn("# Recon Pipeline Comparison", (output / "comparison.md").read_text())


if __name__ == "__main__":
    unittest.main()
