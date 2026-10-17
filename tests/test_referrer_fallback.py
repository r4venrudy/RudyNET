import unittest
from modules.web_security import check_referrer_policy as check
class ReferrerFallbackTests(unittest.TestCase):
 def test_only_recognized_referrer_tokens_participate_in_fallback(self):
  self.assertFalse(check('unsafe-url, future-policy')[0])
  self.assertFalse(check('future-policy')[0])
  self.assertTrue(check('strict-origin, future-policy')[0])
  self.assertTrue(check('future-policy, same-origin')[0])
