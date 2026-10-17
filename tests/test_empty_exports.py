import unittest
from utils.output import render
import csv,io
class EmptyExportTests(unittest.TestCase):
 def test_empty_collections_are_retained_in_flat_reports(self):
  data={'open':[],'details':{},'optional':None}
  rows=dict(list(csv.reader(io.StringIO(render(data,'csv'))))[1:])
  self.assertEqual(rows,{'open':'[]','details':'{}','optional':''})
  self.assertIn('open: []',render(data,'txt'))
