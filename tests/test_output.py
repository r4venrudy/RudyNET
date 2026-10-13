import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.output import export, render  # noqa: E402

DATA = {"target": "example.com", "open": [{"port": 443, "service": "https"}]}


class ExportTests(unittest.TestCase):
    def test_json_round_trips(self):
        self.assertEqual(json.loads(render(DATA, "json")), DATA)

    def test_unknown_format_rejected(self):
        with self.assertRaises(ValueError):
            render(DATA, "xml")

    def test_unknown_extension_falls_back_to_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.log")
            with redirect_stdout(StringIO()):
                export(DATA, None, path)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), DATA)

    def test_format_inferred_from_file_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "report.csv")
            with redirect_stdout(StringIO()):
                export(DATA, None, path)
            with open(path, encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        self.assertEqual(lines[0], "key,value")
        self.assertIn("open.0.port,443", lines)

    def test_no_format_and_no_file_prints_nothing(self):
        out = StringIO()
        with redirect_stdout(out):
            export(DATA, None, None)
        self.assertEqual(out.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
