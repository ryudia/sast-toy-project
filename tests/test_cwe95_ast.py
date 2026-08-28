import unittest
from pathlib import Path

from analyzer.languages.python.cwe95 import analyze_file


TARGET_DIR = Path("dataset/test_targets/python/CWE-95")


class CWE95AstDetectorTests(unittest.TestCase):
    def test_detects_existing_direct_eval_cases(self):
        for filename in (
            "vulnerable_direct_eval.py",
            "vulnerable_flow_eval.py",
        ):
            with self.subTest(filename=filename):
                findings = analyze_file(str(TARGET_DIR / filename))
                self.assertEqual(1, len(findings))
                self.assertEqual("PY-CWE95-EVAL", findings[0]["rule_id"])

    def test_ignores_non_call_text_and_literal_eval(self):
        for filename in (
            "safe_literal_eval.py",
            "safe_eval_comment.py",
            "safe_eval_string.py",
        ):
            with self.subTest(filename=filename):
                self.assertEqual([], analyze_file(str(TARGET_DIR / filename)))

    def test_current_analyzer_does_not_resolve_eval_alias(self):
        findings = analyze_file(str(TARGET_DIR / "alias_vulnerable.py"))
        self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
