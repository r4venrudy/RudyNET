import unittest
from utils.output import render
import csv,io
class CsvKeyTests(unittest.TestCase):
 def test_formula_like_keys_and_newline_values_are_quoted(self):
  rows=list(csv.reader(io.StringIO(render({'=SUM(1,2)':'safe','normal':'\n=1+1'},'csv'))))
  self.assertEqual(rows[1][0],"'=SUM(1,2)")
  self.assertEqual(rows[2][1],"'\n=1+1")
