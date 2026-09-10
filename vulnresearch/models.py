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
    status: str = "potential"
    evidence_level: str = "E1"
    sanitizer: str = "UNKNOWN"
    authentication: str = "UNKNOWN"
    authorization: str = "UNKNOWN"
    reachability: str = "UNKNOWN"

    def to_dict(self) -> Dict:
        return asdict(self)


def dump_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2)


def dump_sarif(findings: List[Finding], tool_name: str = "AI Vulnerability Researcher") -> str:
    results = []
    for finding in findings:
        results.append({
            "ruleId": finding.category,
            "level": "warning",
            "message": {"text": finding.evidence},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": finding.path},
                "region": {"startLine": finding.line, "snippet": {"text": finding.snippet}},
            }}],
            "properties": {
                "status": finding.status,
                "evidenceLevel": finding.evidence_level,
                "confidence": finding.confidence,
            },
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "version": "0.2.0"}},
            "results": results,
        }],
    }, ensure_ascii=False, indent=2)
