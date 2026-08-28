import unittest
from pathlib import Path

from analyzer.languages.python.cwe95_regex import analyze_file


TARGET_DIR = Path("dataset/test_targets/python/CWE-95")


class CWE95RegexDetectorTests(unittest.TestCase):
    def test_detects_direct_eval_text(self):
        findings = analyze_file(str(TARGET_DIR / "vulnerable_direct_eval.py"))

        self.assertEqual(1, len(findings))
        self.assertEqual("PY-CWE95-EVAL-REGEX", findings[0]["rule_id"])
        self.assertEqual(2, findings[0]["line"])

    def test_intentionally_matches_comments_and_strings(self):
        for filename in (
            "safe_eval_comment.py",
            "safe_eval_string.py",
        ):
            with self.subTest(filename=filename):
                self.assertEqual(1, len(analyze_file(str(TARGET_DIR / filename))))

    def test_does_not_match_literal_eval_or_alias_calls(self):
        for filename in (
            "safe_literal_eval.py",
            "alias_vulnerable.py",
        ):
            with self.subTest(filename=filename):
                self.assertEqual([], analyze_file(str(TARGET_DIR / filename)))


if __name__ == "__main__":
    unittest.main()
