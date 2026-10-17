import unittest
from utils.output import render,export
from pathlib import Path
import tempfile
class StrictJsonTests(unittest.TestCase):
 def test_nonfinite_numbers_are_rejected_without_touching_a_saved_report(self):
  for value in [float('nan'),float('inf'),-float('inf')]:
   with self.assertRaises(ValueError): render({'metric':value},'json')
  with tempfile.TemporaryDirectory() as directory:
   file=Path(directory)/'report.json'; file.write_text('existing',encoding='utf-8')
   with self.assertRaises(ValueError): export({'metric':float('nan')},'json',str(file))
   self.assertEqual(file.read_text(),'existing')
