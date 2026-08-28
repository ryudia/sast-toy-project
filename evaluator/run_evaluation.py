import ast
import csv
import os

from analyzer.languages.python.cwe95 import analyze_target as analyze_ast_target
from analyzer.languages.python.cwe95_regex import analyze_target as analyze_regex_target
from analyzer.models.normalizer import normalize_findings
from evaluator.evaluator import Evaluator


DETECTORS = (
    ("Regex Baseline", analyze_regex_target),
    ("AST Analyzer", analyze_ast_target),
)


def load_ground_truth(csv_path: str) -> dict:
    """
    Ground Truth CSV를 읽어서
    {파일명: 취약 여부} 형태의 딕셔너리로 변환합니다.
    """
    ground_truth = {}

    if not os.path.exists(csv_path):
        print(f"[!] Ground Truth file not found: {csv_path}")
        return ground_truth

    with open(csv_path, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            filename = row["file"]
            expected = row["expected"]

            is_vulnerable = expected.strip().lower() == "true"

            ground_truth[filename] = is_vulnerable

    return ground_truth


def build_detections(ground_truth: dict, findings: list) -> dict:
    """
    Detector Finding 목록을
    {파일명: 탐지 여부} 형태의 딕셔너리로 변환합니다.
    """

    # Ground Truth에 있는 모든 파일을 우선 미탐지(False) 상태로 초기화
    detections = {
        filename: False
        for filename in ground_truth
    }

    for finding in findings:
        filepath = finding.file

        # Detector는 전체 경로를 반환하므로 파일명만 추출
        filename = os.path.basename(filepath)

        if filename in detections:
            detections[filename] = True

    return detections


def validate_labeled_targets(ground_truth: dict, target_dir: str) -> None:
    """Fail before evaluation when a labeled Python target cannot be analyzed."""
    for filename in ground_truth:
        target_path = os.path.join(target_dir, filename)

        if not os.path.isfile(target_path):
            raise FileNotFoundError(
                f"Ground Truth target file not found: {target_path}"
            )

        with open(target_path, "r", encoding="utf-8") as target_file:
            source_code = target_file.read()

        ast.parse(source_code, filename=target_path)


def analyze_labeled_targets(
    ground_truth: dict,
    target_dir: str,
    analyze_target,
) -> list:
    """Run a detector against exactly the files labeled in Ground Truth."""
    findings = []

    for filename in ground_truth:
        target_path = os.path.join(target_dir, filename)
        findings.extend(analyze_target(target_path))

    return findings


def compare_detectors(ground_truth: dict, target_dir: str) -> dict:
    """Evaluate every detector with the same labels and target files."""
    comparison = {}
    validate_labeled_targets(ground_truth, target_dir)

    for detector_name, analyze_target in DETECTORS:
        raw_findings = analyze_labeled_targets(
            ground_truth,
            target_dir,
            analyze_target,
        )
        findings = normalize_findings(
            raw_findings,
            language="python",
            severity="high",
        )
        detections = build_detections(ground_truth, findings)
        comparison[detector_name] = Evaluator(
            ground_truth,
            detections,
        ).evaluate()

    return comparison


def print_comparison(comparison: dict) -> None:
    print("Detector Comparison")
    print("-" * 81)
    print(
        f"{'Detector':<18} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} "
        f"{'Precision':>12} {'Recall':>12}"
    )
    print("-" * 81)

    for detector_name, results in comparison.items():
        print(
            f"{detector_name:<18} "
            f"{results['TP']:>4} "
            f"{results['FP']:>4} "
            f"{results['FN']:>4} "
            f"{results['TN']:>4} "
            f"{results['Precision']:>12.4f} "
            f"{results['Recall']:>12.4f}"
        )


def run_evaluation(
    ground_truth_path: str = os.path.join(
        "dataset",
        "ground_truth",
        "python_cwe95.csv",
    ),
    target_dir: str = os.path.join(
        "dataset",
        "test_targets",
        "python",
        "CWE-95",
    ),
) -> dict:
    # Ground Truth CSV를 읽어와서 {파일명: 취약 여부} 딕셔너리로 변환
    print(f"[*] Loading Ground Truth from {ground_truth_path}...")

    ground_truth = load_ground_truth(ground_truth_path)

    if not ground_truth:
        print("[!] Ground Truth data is empty.")
        return {}

    # 두 Detector를 동일한 라벨 대상에 실행하고 비교
    print(
        f"[*] Running Regex Baseline and AST Analyzer on "
        f"{len(ground_truth)} labeled targets in {target_dir}..."
    )
    comparison = compare_detectors(ground_truth, target_dir)

    print("[*] Evaluating detection performance...\n")
    print_comparison(comparison)

    return comparison


if __name__ == "__main__":
    run_evaluation()
