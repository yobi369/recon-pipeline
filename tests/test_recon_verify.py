import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import recon_verify


class VerifyTests(unittest.TestCase):
    def make_manifest(self, directory):
        root = Path(directory)
        payload = b'{"evidence":true}\n'
        (root / "report.json").write_bytes(payload)
        manifest = {
            "manifest_schema_version": "1.0",
            "tool": "Recon Pipeline",
            "artifacts": [{
                "path": "report.json",
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "media_type": "application/json",
            }],
        }
        path = root / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def test_verifies_valid_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            result = recon_verify.verify_manifest(self.make_manifest(directory))
            self.assertEqual(result["status"], "verified")
            self.assertEqual(result["artifacts_verified"], 1)

    def test_detects_modified_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.make_manifest(directory)
            (Path(directory) / "report.json").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "integrity check failed"):
                recon_verify.verify_manifest(manifest)

    def test_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.make_manifest(directory)
            data = json.loads(manifest.read_text())
            data["artifacts"][0]["path"] = "../outside.json"
            manifest.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsafe artifact path"):
                recon_verify.verify_manifest(manifest)

    def test_rejects_duplicate_artifact_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.make_manifest(directory)
            data = json.loads(manifest.read_text())
            data["artifacts"].append(dict(data["artifacts"][0]))
            manifest.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate artifact path"):
                recon_verify.verify_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
