import ast
import os
import sys


class CWE95Detector(ast.NodeVisitor):
    def __init__(self, filepath):
        self.filepath = filepath
        self.findings = []

    def visit_Call(self, node):
        # 직접적인 eval(...) 호출 탐지
        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            self.findings.append(
                {
                    "rule_id": "PY-CWE95-EVAL",
                    "cwe": "CWE-95",
                    "file": self.filepath,
                    "line": node.lineno,
                    "col": node.col_offset,
                    "message": "Unsafe use of dynamic eval() detected.",
                }
            )

        # 하위 AST 노드 계속 탐색
        self.generic_visit(node)


def analyze_file(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            source_code = file.read()

        tree = ast.parse(source_code, filename=filepath)

        detector = CWE95Detector(filepath)
        detector.visit(tree)

        return detector.findings

    except (OSError, SyntaxError) as error:
        print(
            f"Error analyzing {filepath}: {error}",
            file=sys.stderr,
        )
        return []


def analyze_target(target):
    findings = []

    if os.path.isfile(target):
        if target.endswith(".py"):
            findings.extend(analyze_file(target))

        return findings

    if os.path.isdir(target):
        for root, _, files in os.walk(target):
            for filename in files:
                if not filename.endswith(".py"):
                    continue

                filepath = os.path.join(root, filename)
                findings.extend(analyze_file(filepath))

        return findings

    print(
        f"Target does not exist: {target}",
        file=sys.stderr,
    )

    return findings


def print_report(findings):
    if not findings:
        print("[+] No CWE-95 findings detected.")
        return

    print(f"[!] Findings detected: {len(findings)}")

    for finding in findings:
        print(
            f" - [{finding['rule_id']}] "
            f"{finding['file']} "
            f"(Line {finding['line']}, Col {finding['col']}): "
            f"{finding['message']}"
        )


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python cwe95.py <target_file_or_directory>",
            file=sys.stderr,
        )
        sys.exit(2)

    target = sys.argv[1]

    findings = analyze_target(target)
    print_report(findings)

    if findings:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()