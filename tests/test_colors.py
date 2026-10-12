import importlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class ColorTests(unittest.TestCase):
    def test_no_color_env_disables_escape_codes(self):
        with mock.patch.dict(os.environ, {"NO_COLOR": "1"}):
            import utils.colors as colors
            colors = importlib.reload(colors)
            self.assertEqual(colors.Colors.RED, "")
            self.assertEqual(colors.Colors.grade("A+"), "A+")

    def test_grade_keeps_the_letter(self):
        import utils.colors as colors
        self.assertIn("F", colors.Colors.grade("F"))


if __name__ == "__main__":
    unittest.main()
