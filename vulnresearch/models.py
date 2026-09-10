"""Unified vulnerability object model (PHASE 26).

Keeps the legacy ``Finding`` dataclass for backward compatibility with the
v0.1.x regex scanner and adds the full ``Vulnerability`` object required by
the AI Vulnerability Researcher SKILL.  Every field maps to a PHASE 26 slot;
missing information is explicitly stored as ``"UNKNOWN"`` rather than guessed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Legacy Finding (v0.1.x compatibility – do not remove)
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """Lightweight finding produced by the regex fallback scanner."""

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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_vulnerability(self, vuln_id: str = "") -> "Vulnerability":
        """Convert a legacy Finding into the full Vulnerability object."""
        vid = vuln_id or f"VULN-{abs(hash((self.category, self.path, self.line))) % 100000:05d}"
        return Vulnerability(
            id=vid,
            title=self.title,
            category=self.category,
            severity=self.severity,
            status=self.status,
            confidence=self.confidence,
            file=self.path,
            line=self.line,
            snippet=self.snippet,
            sink=SinkInfo(type=self.sink or self.category, location=f"{self.path}:{self.line}"),
            evidence=EvidenceInfo(level=self.evidence_level, proof=self.evidence),
            root_cause=self.root_cause,
            variants=list(self.variants),
            remediation=self.remediation,
            sanitizer=SanitizerInfo(present=self.sanitizer),
            authentication=AuthInfo(required=self.authentication),
            authorization=AuthInfo(required=self.authorization),
            reachability=ReachabilityInfo(status=self.reachability),
        )


# ---------------------------------------------------------------------------
# Sub-objects for the unified Vulnerability
# ---------------------------------------------------------------------------

@dataclass
class SourceInfo:
    """Where attacker-controllable input enters (PHASE 3)."""

    type: str = "UNKNOWN"  # http_query, http_body, file_path, env_var, …
    location: str = ""
    description: str = ""


@dataclass
class DataFlowStep:
    """One hop in SOURCE → TRANSFORM → SANITIZER → SINK (PHASE 20)."""

    step: str = ""
    location: str = ""
    transformation: str = ""


@dataclass
class SanitizerInfo:
    present: str = "UNKNOWN"  # YES / NO / UNKNOWN
    description: str = ""


@dataclass
class AuthInfo:
    """Used for both authentication and authorization slots."""

    required: str = "UNKNOWN"  # YES / NO / UNKNOWN
    status: str = "UNKNOWN"    # PRESENT / MISSING / BYPASSED / UNKNOWN


@dataclass
class ReachabilityInfo:
    status: str = "UNKNOWN"  # REACHABLE / UNREACHABLE / UNKNOWN
    conditions: str = ""


@dataclass
class SinkInfo:
    type: str = ""
    location: str = ""


@dataclass
class ImpactInfo:
    confidentiality: str = "UNKNOWN"
    integrity: str = "UNKNOWN"
    availability: str = "UNKNOWN"
    privilege: str = "UNKNOWN"


@dataclass
class EvidenceInfo:
    level: str = "E1"  # E0–E5 (PHASE 14)
    proof: str = ""


@dataclass
class VerificationInfo:
    environment: str = "static"  # static / unit / integration / docker / authorized
    method: str = ""
    result: str = ""


# ---------------------------------------------------------------------------
# Unified Vulnerability (PHASE 26)
# ---------------------------------------------------------------------------

@dataclass
class Vulnerability:
    """Full vulnerability object with every PHASE 26 field.

    Fields default to *empty / UNKNOWN* so that the evidence engine can
    upgrade or downgrade them as analysis deepens.
    """

    id: str
    title: str
    category: str
    severity: str  # Critical / High / Medium / Low / Info
    status: str = "potential"  # confirmed / likely / potential / rejected
    confidence: str = "Low"    # High / Medium / Low

    # location
    file: str = ""
    line: int = 0
    function: str = ""
    snippet: str = ""

    # evidence chain (PHASE 20)
    source: SourceInfo = field(default_factory=SourceInfo)
    data_flow: List[DataFlowStep] = field(default_factory=list)
    sanitizer: SanitizerInfo = field(default_factory=SanitizerInfo)
    authentication: AuthInfo = field(default_factory=AuthInfo)
    authorization: AuthInfo = field(default_factory=AuthInfo)
    reachability: ReachabilityInfo = field(default_factory=ReachabilityInfo)
    sink: SinkInfo = field(default_factory=SinkInfo)
    impact: ImpactInfo = field(default_factory=ImpactInfo)
    evidence: EvidenceInfo = field(default_factory=EvidenceInfo)

    # research loop
    root_cause: str = ""
    variants: List[str] = field(default_factory=list)
    vulnerability_family: str = ""

    # verification & remediation
    verification: VerificationInfo = field(default_factory=VerificationInfo)
    remediation: str = ""

    # -- helpers -----------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_finding(self) -> Finding:
        """Round-trip back to a legacy Finding for old consumers."""
        return Finding(
            title=self.title,
            category=self.category,
            severity=self.severity,
            confidence=self.confidence,
            evidence=self.evidence.proof,
            path=self.file,
            line=self.line,
            snippet=self.snippet,
            source=self.source.type,
            sink=self.sink.type,
            root_cause=self.root_cause,
            variants=list(self.variants),
            remediation=self.remediation,
            status=self.status,
            evidence_level=self.evidence.level,
            sanitizer=self.sanitizer.present,
            authentication=self.authentication.required,
            authorization=self.authorization.required,
            reachability=self.reachability.status,
        )


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def dump_json(findings: List[Any]) -> str:
    """Serialise a list of Finding *or* Vulnerability objects to JSON."""
    data = []
    for f in findings:
        if isinstance(f, Vulnerability):
            data.append(f.to_dict())
        else:
            data.append(f.to_dict())
    return json.dumps(data, ensure_ascii=False, indent=2)


def dump_sarif(findings: List[Any], tool_name: str = "AI Vulnerability Researcher") -> str:
    """Serialise findings to SARIF 2.1.0.  Accepts Finding or Vulnerability."""
    results = []
    for f in findings:
        if isinstance(f, Vulnerability):
            path = f.file
            line = f.line
            snippet = f.snippet
            category = f.category
            evidence_text = f.evidence.proof
            status = f.status
            ev_level = f.evidence.level
            conf = f.confidence
        else:
            path = f.path
            line = f.line
            snippet = f.snippet
            category = f.category
            evidence_text = f.evidence
            status = f.status
            ev_level = f.evidence_level
            conf = f.confidence

        results.append({
            "ruleId": category,
            "level": "warning",
            "message": {"text": evidence_text},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": path},
                "region": {"startLine": line, "snippet": {"text": snippet}},
            }}],
            "properties": {
                "status": status,
                "evidenceLevel": ev_level,
                "confidence": conf,
            },
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool_name, "version": "0.4.4"}},
            "results": results,
        }],
    }, ensure_ascii=False, indent=2)
