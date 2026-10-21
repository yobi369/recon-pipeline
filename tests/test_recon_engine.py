import argparse
import unittest
from unittest import mock
import recon_engine as recon

class ScopeTests(unittest.TestCase):
    def test_domain_normalization(self):
        self.assertEqual(recon.normalize_domain("Example.COM."), "example.com")
    def test_rejects_urls_and_injection(self):
        for value in ("https://example.com", "example.com/path", "example.com;id", "example.com:443"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                recon.normalize_domain(value)
    def test_rejects_ip_literals(self):
        for value in ("127.0.0.1", "2001:db8::1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                recon.normalize_domain(value)
    def test_scope_suffix_boundary(self):
        self.assertTrue(recon.in_scope("api.example.com", "example.com"))
        self.assertTrue(recon.in_scope("example.com", "example.com"))
        self.assertFalse(recon.in_scope("example.com.attacker.test", "example.com"))
        self.assertFalse(recon.in_scope("notexample.com", "example.com"))
    def test_authorization_required_before_network(self):
        args = argparse.Namespace(target="example.com", authorized=False, workers=1, max_hosts=1,
                                  timeout=1.0, ports=None, no_http=True)
        with self.assertRaisesRegex(ValueError, "authorization acknowledgement"):
            recon.run(args)

if __name__ == "__main__":
    unittest.main()


class ExecutionTests(unittest.TestCase):
    def args(self, **overrides):
        values = dict(target="example.com", authorized=True, workers=2, max_hosts=10,
                      timeout=1.0, ports=None, no_http=True)
        values.update(overrides)
        return argparse.Namespace(**values)

    @mock.patch("recon_engine.resolve")
    @unittest.mock.patch("recon_engine.discover")
    def test_run_filters_out_of_scope_discovery(self, discover, resolve):
        discover.return_value = ({"example.com", "api.example.com", "example.com.attacker.test"}, [])
        resolve.side_effect = lambda host: {
            "host": host, "addresses": ["192.0.2.10"], "dns_resolved": True,
            "dns_errors": [], "http": [], "elapsed_ms": 0,
        }
        report = recon.run(self.args())
        self.assertEqual([h["host"] for h in report["hosts"]], ["api.example.com", "example.com"])
        self.assertEqual(report["scope"]["root_domain"], "example.com")
        self.assertEqual(report["summary"]["names_discovered"], 2)
        self.assertIn("started_at", report)
        self.assertIn("completed_at", report)
        self.assertGreaterEqual(report["duration_seconds"], 0)
        self.assertEqual(len(report["run_id"]), 22)
        discover.assert_called_once_with("example.com", 1.0)

    @unittest.mock.patch("recon_engine.discover")
    def test_invalid_ports_fail_before_discovery(self, discover):
        with self.assertRaisesRegex(ValueError, "ports must be comma-separated integers"):
            recon.run(self.args(ports="80,abc"))
        discover.assert_not_called()

    @unittest.mock.patch("recon_engine.discover")
    def test_port_count_is_bounded(self, discover):
        ports = ",".join(str(p) for p in range(1, 34))
        with self.assertRaisesRegex(ValueError, "up to 32 TCP ports"):
            recon.run(self.args(ports=ports))
        discover.assert_not_called()

    def test_report_files_are_written(self):
        import json
        import tempfile
        from pathlib import Path
        fixture = {
            "schema_version": "1.0", "tool": "Recon Pipeline", "tool_version": recon.VERSION,
            "run_id": "20261021T000000Z", "started_at": "2026-10-21T00:00:00+00:00",
            "scope": {"root_domain": "example.com", "authorization_acknowledged": True},
            "summary": {"names_discovered": 1, "dns_resolved_hosts": 1,
                        "hosts_with_http_response": 0, "tcp_ports_open": 0, "errors": 0},
            "hosts": [{"host": "example.com", "addresses": ["192.0.2.10"], "http": []}],
            "tcp_observations": [], "errors": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            with unittest.mock.patch("recon_engine.run", return_value=fixture):
                self.assertEqual(recon.main(["example.com", "--authorized", "--output-dir", directory]), 0)
            out = Path(directory)
            self.assertEqual(json.loads((out / "report.json").read_text())["scope"]["root_domain"], "example.com")
            self.assertIn("# Reconnaissance Report", (out / "report.md").read_text())
            self.assertEqual((out / "run.log").read_text(), "")

