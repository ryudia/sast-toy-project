from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Finding:
    rule_id: str
    language: str
    cwe: str
    severity: str
    file: str
    line: int
    evidence: str
    message: str
    col: Optional[int] = None
