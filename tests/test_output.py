import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.output import OutputFormatter, export, render  # noqa: E402
from contextlib import redirect_stderr  # noqa: E402

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


class PipeTests(unittest.TestCase):
    def test_json_to_stdout_is_not_mixed_with_the_human_view(self):
        out, err = StringIO(), StringIO()
        scan = {"target": "h", "ip": "1.2.3.4", "scanned": 1, "scan_type": "tcp", "open": []}
        with redirect_stdout(out), redirect_stderr(err):
            OutputFormatter.display_scan_results(scan, "json", None)
        self.assertEqual(json.loads(out.getvalue()), scan)
        self.assertIn("No open ports", err.getvalue())


if __name__ == "__main__":
    unittest.main()


class CsvSafetyTests(unittest.TestCase):
    def test_formula_like_values_are_quoted(self):
        text = render({"banner": "=HYPERLINK(\"http://x\")", "port": -1, "name": "www"}, "csv")
        self.assertIn("banner,\"'=HYPERLINK(\"\"http://x\"\")\"", text)
        self.assertIn("port,-1", text)
        self.assertIn("name,www", text)
