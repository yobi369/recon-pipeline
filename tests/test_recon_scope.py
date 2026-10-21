import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import recon_scope


def sample(**changes):
    data = {
        "schema_version": "1.0",
        "engagement_id": "ENG-2026-001",
        "authorization_reference": "ROE-123",
        "root_domain": "example.com",
        "expires_at": "2099-01-01T00:00:00Z",
        "allowed_hosts": ["example.com", "api.example.com"],
        "excluded_hosts": ["admin.example.com"],
    }
    data.update(changes)
    return data


class ScopeManifestTests(unittest.TestCase):
    def write_scope(self, directory, data):
        path = Path(directory) / "scope.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_loads_valid_scope_and_records_digest(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_scope(directory, sample())
            scope = recon_scope.load_scope(path, "example.com")
            self.assertEqual(scope["engagement_id"], "ENG-2026-001")
            self.assertEqual(scope["authorization_reference"], "ROE-123")
            self.assertEqual(scope["scope_file_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_allowlist_and_exclusions_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            scope = recon_scope.load_scope(self.write_scope(directory, sample()), "example.com")
            self.assertTrue(recon_scope.host_is_in_scope("example.com", scope))
            self.assertTrue(recon_scope.host_is_in_scope("v2.api.example.com", scope))
            self.assertFalse(recon_scope.host_is_in_scope("www.example.com", scope))
            self.assertFalse(recon_scope.host_is_in_scope("admin.example.com", scope))
            self.assertFalse(recon_scope.host_is_in_scope("x.admin.example.com", scope))
            self.assertFalse(recon_scope.host_is_in_scope("example.com.attacker.test", scope))

    def test_rejects_expired_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_scope(directory, sample(expires_at="2000-01-01T00:00:00Z"))
            with self.assertRaisesRegex(ValueError, "expired"):
                recon_scope.load_scope(path, "example.com")

    def test_rejects_target_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_scope(directory, sample())
            with self.assertRaisesRegex(ValueError, "target must match"):
                recon_scope.load_scope(path, "other.example.com")

    def test_rejects_out_of_root_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_scope(directory, sample(allowed_hosts=["attacker.test"]))
            with self.assertRaisesRegex(ValueError, "outside root_domain"):
                recon_scope.load_scope(path, "example.com")

    def test_requires_timezone_and_authorization_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            no_zone = self.write_scope(directory, sample(expires_at="2099-01-01T00:00:00"))
            with self.assertRaisesRegex(ValueError, "timezone"):
                recon_scope.load_scope(no_zone, "example.com")
            no_ref = self.write_scope(directory, sample(authorization_reference=" "))
            with self.assertRaisesRegex(ValueError, "authorization_reference"):
                recon_scope.load_scope(no_ref, "example.com")


if __name__ == "__main__":
    unittest.main()
