import tempfile
import unittest
from pathlib import Path

from analyzer.languages.python.cwe95 import analyze_file as analyze_ast_file
from analyzer.languages.python.cwe95_regex import analyze_file as analyze_regex_file
from analyzer.models.finding import Finding
from analyzer.models.normalizer import normalize_findings
from evaluator.run_evaluation import compare_detectors, load_ground_truth


GROUND_TRUTH_PATH = Path("dataset/ground_truth/python_cwe95.csv")
TARGET_DIR = Path("dataset/test_targets/python/CWE-95")


class DetectorComparisonTests(unittest.TestCase):
    def test_ground_truth_labels_exactly_the_python_targets(self):
        ground_truth = load_ground_truth(str(GROUND_TRUTH_PATH))
        labeled_files = set(ground_truth)
        target_files = {path.name for path in TARGET_DIR.glob("*.py")}

        self.assertEqual(target_files, labeled_files)

    def test_both_detectors_produce_expected_metrics_on_shared_ground_truth(self):
        ground_truth = load_ground_truth(str(GROUND_TRUTH_PATH))

        comparison = compare_detectors(ground_truth, str(TARGET_DIR))

        self.assertEqual(
            {
                "TP": 2,
                "FP": 2,
                "FN": 1,
                "TN": 1,
                "Precision": 0.5,
                "Recall": 2 / 3,
            },
            comparison["Regex Baseline"],
        )
        self.assertEqual(
            {
                "TP": 2,
                "FP": 0,
                "FN": 1,
                "TN": 3,
                "Precision": 1.0,
                "Recall": 2 / 3,
            },
            comparison["AST Analyzer"],
        )

    def test_both_detector_outputs_share_the_normalized_finding_model(self):
        target = str(TARGET_DIR / "vulnerable_direct_eval.py")

        for analyze_file in (analyze_regex_file, analyze_ast_file):
            with self.subTest(analyze_file=analyze_file.__module__):
                findings = normalize_findings(
                    analyze_file(target),
                    language="python",
                    severity="high",
                )

                self.assertEqual(1, len(findings))
                self.assertIsInstance(findings[0], Finding)
                self.assertEqual("python", findings[0].language)
                self.assertEqual("high", findings[0].severity)
                self.assertEqual("    eval(user_input)", findings[0].evidence)

    def test_invalid_labeled_python_aborts_instead_of_counting_a_negative(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            invalid_target = Path(temp_dir) / "invalid.py"
            invalid_target.write_text("eval(\n", encoding="utf-8")

            with self.assertRaises(SyntaxError):
                compare_detectors(
                    {"invalid.py": False},
                    temp_dir,
                )


if __name__ == "__main__":
    unittest.main()
