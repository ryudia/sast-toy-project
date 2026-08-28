import os
import re
import sys


EVAL_CALL_PATTERN = re.compile(r"\beval\s*\(")


def analyze_file(filepath):
    findings = []

    try:
        with open(filepath, "r", encoding="utf-8") as file:
            source_code = file.read()
    except OSError as error:
        print(
            f"Error analyzing {filepath}: {error}",
            file=sys.stderr,
        )
        return findings

    for line_number, line in enumerate(source_code.splitlines(), start=1):
        for match in EVAL_CALL_PATTERN.finditer(line):
            findings.append(
                {
                    "rule_id": "PY-CWE95-EVAL-REGEX",
                    "cwe": "CWE-95",
                    "file": filepath,
                    "line": line_number,
                    "col": match.start(),
                    "message": "Text matching eval(...) detected by Regex baseline.",
                }
            )

    return findings


def analyze_target(target):
    findings = []

    if os.path.isfile(target):
        if target.endswith(".py"):
            findings.extend(analyze_file(target))

        return findings

    if os.path.isdir(target):
        for root, _, files in os.walk(target):
            for filename in sorted(files):
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
        print("[+] No CWE-95 Regex baseline findings detected.")
        return

    print(f"[!] Regex baseline findings detected: {len(findings)}")

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
            "Usage: python cwe95_regex.py <target_file_or_directory>",
            file=sys.stderr,
        )
        sys.exit(2)

    findings = analyze_target(sys.argv[1])
    print_report(findings)

    if findings:
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
