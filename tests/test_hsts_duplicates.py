import unittest
from modules.web_security import check_hsts as check
class HstsDuplicateTests(unittest.TestCase):
 def test_duplicate_directives_and_signed_max_age_are_not_strong_hsts(self):
  for value in ['max-age=0; max-age=31536000','max-age=31536000; max-age=31536000','max-age=31536000; includeSubDomains; includeSubDomains','max-age=+31536000']:
   self.assertFalse(check(value)[0],value)
  self.assertTrue(check('max-age="31536000"; includeSubDomains')[0])
