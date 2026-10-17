import unittest
from click.testing import CliRunner
import rudynet
class DiagnosticStreams(unittest.TestCase):
 def test_errors_do_not_corrupt_machine_stdout(self):
  # Click 8.1 (Python 3.9) mixes stderr by default; Click 8.2+ separates it.
  try: runner=CliRunner(mix_stderr=False)
  except TypeError: runner=CliRunner()
  for arguments in [['scan','-t','127.0.0.1','-p','bad'],['web','-u','ftp://example.com'],['subdomain','-d','example.com','-w','no-such-wordlist']]:
   result=runner.invoke(rudynet.cli,arguments+['-o','json'])
   self.assertEqual(result.exit_code,1)
   self.assertEqual(result.stdout,'')
   self.assertIn('Error:',result.stderr)
