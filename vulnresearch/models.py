from dataclasses import dataclass, field, asdict
from typing import List, Dict
import json

@dataclass
class Finding:
    title: str
    category: str
    severity: str
    confidence: str
    evidence: str
    path: str
    line: int
    snippet: str
    source: str = ""
    sink: str = ""
    root_cause: str = ""
    variants: List[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


def dump_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2)
