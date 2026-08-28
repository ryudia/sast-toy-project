from analyzer.models.finding import Finding


def read_evidence(filepath: str, line_number: int) -> str:
    with open(filepath, "r", encoding="utf-8") as source_file:
        for current_line, source_line in enumerate(source_file, start=1):
            if current_line == line_number:
                return source_line.rstrip("\r\n")

    return ""


def normalize_finding(
    raw_finding: dict,
    *,
    language: str,
    severity: str,
) -> Finding:
    filepath = raw_finding["file"]
    line_number = raw_finding["line"]
    evidence = raw_finding.get("evidence")

    if evidence is None:
        evidence = read_evidence(filepath, line_number)

    return Finding(
        rule_id=raw_finding["rule_id"],
        language=language,
        cwe=raw_finding["cwe"],
        severity=severity,
        file=filepath,
        line=line_number,
        evidence=evidence,
        message=raw_finding["message"],
        col=raw_finding.get("col"),
    )


def normalize_findings(
    raw_findings: list[dict],
    *,
    language: str,
    severity: str,
) -> list[Finding]:
    return [
        normalize_finding(
            raw_finding,
            language=language,
            severity=severity,
        )
        for raw_finding in raw_findings
    ]
