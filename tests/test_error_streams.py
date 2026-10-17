import unittest
from click.testing import CliRunner
import rudynet
class DiagnosticStreams(unittest.TestCase):
 def test_errors_do_not_corrupt_machine_stdout(self):
  for arguments in [['scan','-t','127.0.0.1','-p','bad'],['web','-u','ftp://example.com'],['subdomain','-d','example.com','-w','no-such-wordlist']]:
   result=CliRunner().invoke(rudynet.cli,arguments+['-o','json'])
   self.assertEqual(result.exit_code,1)
   self.assertEqual(result.stdout,'')
   self.assertIn('Error:',result.stderr)
