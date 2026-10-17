import unittest
from modules.web_security import check_csp as check
class CspNonceScopeTests(unittest.TestCase):
 def test_unrelated_nonce_does_not_mask_unsafe_scripts(self):
  self.assertFalse(check("script-src 'unsafe-inline'; style-src 'nonce-abc'")[0])
  self.assertFalse(check("report-uri https://example.com/default-src")[0])
  self.assertFalse(check("script-src 'unsafe-inline'; script-src 'nonce-abc'")[0])
  self.assertFalse(check("script-src 'unsafe-inline' 'nonce-'")[0])
  self.assertTrue(check("script-src 'unsafe-inline' 'nonce-abc'")[0])
