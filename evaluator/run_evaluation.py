import csv
import os

from analyzer.languages.python.cwe95 import analyze_target
from evaluator.evaluator import Evaluator


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
        filepath = finding["file"]

        # Detector는 전체 경로를 반환하므로 파일명만 추출
        filename = os.path.basename(filepath)

        if filename in detections:
            detections[filename] = True

    return detections


def run_evaluation():
    # 1. 평가 데이터 경로
    ground_truth_path = os.path.join(
        "dataset",
        "ground_truth",
        "python_cwe95.csv",
    )

    target_dir = os.path.join(
        "dataset",
        "test_targets",
        "python",
        "CWE-95",
    )

    # 2. Ground Truth 로딩
    print(f"[*] Loading Ground Truth from {ground_truth_path}...")

    ground_truth = load_ground_truth(ground_truth_path)

    if not ground_truth:
        print("[!] Ground Truth data is empty.")
        return

    # 3. CWE-95 Detector 실행
    print(f"[*] Running CWE-95 detector on {target_dir}...")

    findings = analyze_target(target_dir)

    # 4. Finding -> Detection 결과 변환
    detections = build_detections(
        ground_truth,
        findings,
    )

    # 5. Ground Truth와 Detector 결과 비교
    print("[*] Evaluating detection performance...\n")

    evaluator = Evaluator(
        ground_truth,
        detections,
    )

    evaluator.print_results()


if __name__ == "__main__":
    run_evaluation()