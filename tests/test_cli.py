import os
import sys
import unittest
from unittest import mock

from click.testing import CliRunner

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import rudynet  # noqa: E402


class _FakeWeb:
    def __init__(self, url, timeout):
        pass

    def full_analysis(self):
        return {"target": "https://example.com", "score": 62, "grade": "C"}


class FailUnderTests(unittest.TestCase):
    def run_web(self, *args):
        with mock.patch.object(rudynet, "load_module", return_value=_FakeWeb):
            return CliRunner().invoke(rudynet.cli, ["web", "-u", "example.com", *args])

    def test_exit_code_2_below_threshold(self):
        self.assertEqual(self.run_web("--fail-under", "70").exit_code, 2)

    def test_exit_code_0_at_or_above_threshold(self):
        self.assertEqual(self.run_web("--fail-under", "62").exit_code, 0)
        self.assertEqual(self.run_web().exit_code, 0)
