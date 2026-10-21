import argparse
import unittest
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
