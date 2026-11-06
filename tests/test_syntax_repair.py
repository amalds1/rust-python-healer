"""Conservative syntax patch tests; source programs are never executed."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("syntax_colon", ROOT / "python" / "syntax_colon.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


class SyntaxRepairTests(unittest.TestCase):
    def test_missing_colon_on_if(self):
        self.assertEqual(module.propose("if True\n    answer = 42\n"),
                         "if True:\n    answer = 42\n")

    def test_missing_colon_before_comment(self):
        self.assertEqual(module.propose("if 'a#b' # a comment\n    pass\n"),
                         "if 'a#b': # a comment\n    pass\n")

    def test_def_missing_colon(self):
        self.assertEqual(module.propose("def answer()\n    return 42\n"),
                         "def answer():\n    return 42\n")

    def test_valid_source_unchanged(self):
        self.assertIsNone(module.propose("if True:\n    pass\n"))

    def test_non_header_syntax_error_not_guessed(self):
        self.assertIsNone(module.propose("return 42\n"))

    def test_multi_line_header_not_guessed(self):
        self.assertIsNone(module.propose("if (\n    True\n)\n    pass\n"))

    def test_missing_colon_does_not_execute_source(self):
        # It is valid after the patch, but compiling cannot execute a raise.
        self.assertEqual(module.propose("if True\n    raise RuntimeError('not executed')\n"),
                         "if True:\n    raise RuntimeError('not executed')\n")


if __name__ == "__main__":
    unittest.main()
