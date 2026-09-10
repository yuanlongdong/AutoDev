"""Tests for vulnresearch.evidence_engine (PHASE 14)."""
from __future__ import annotations

from vulnresearch.evidence_engine import EvidenceEngine, evidence_label
from vulnresearch.models import (
    AuthInfo,
    DataFlowStep,
    ImpactInfo,
    ReachabilityInfo,
    SanitizerInfo,
    SinkInfo,
    SourceInfo,
    VerificationInfo,
    Vulnerability,
)


def _vuln(**kw) -> Vulnerability:
    base = dict(id="V-001", title="sql injection", category="sql-injection",
                severity="High")
    base.update(kw)
    return Vulnerability(**base)


def test_evidence_label_strings():
    assert evidence_label("E0").startswith("E0")
    assert "Source" in evidence_label("E2")
    assert evidence_label("E99").endswith("unknown evidence level")


def test_default_start_is_e1():
    v = _vuln(sink=SinkInfo(type="execute"))
    out = EvidenceEngine().evaluate(v)
    assert out.evidence.level == "E1"


def test_e0_when_nothing_but_speculation():
    v = _vuln()  # no source, no sink
    EvidenceEngine().evaluate(v)
    assert v.evidence.level == "E0"


def test_e1_to_e2_upgrade():
    v = _vuln(sink=SinkInfo(type="execute"))
    EvidenceEngine().evaluate(v)
    assert v.evidence.level == "E1"

    v.source = SourceInfo(type="http_query")
    v.data_flow.append(DataFlowStep(step="tainted_id", location="app.py:3",
                                    transformation="assignment"))
    EvidenceEngine().evaluate(v)
    assert v.evidence.level == "E2"
    assert "upgrade" in v.evidence.proof


def test_e2_to_e3_upgrade():
    v = _vuln(
        sink=SinkInfo(type="execute"),
        source=SourceInfo(type="http_query"),
        data_flow=[DataFlowStep(step="tainted_id", location="app.py:3")],
        reachability=ReachabilityInfo(status="REACHABLE"),
        sanitizer=SanitizerInfo(present="NO"),
        authorization=AuthInfo(required="YES", status="MISSING"),
    )
    EvidenceEngine().evaluate(v)
    assert v.evidence.level == "E3"


def test_e4_reproduction_and_e5_impact():
    v = _vuln(
        sink=SinkInfo(type="execute"),
        source=SourceInfo(type="http_query"),
        data_flow=[DataFlowStep(step="x")],
        reachability=ReachabilityInfo(status="REACHABLE"),
        sanitizer=SanitizerInfo(present="NO"),
        authorization=AuthInfo(required="YES", status="MISSING"),
        verification=VerificationInfo(method="poc.py", result="successfully confirmed"),
        impact=ImpactInfo(confidentiality="HIGH", integrity="UNKNOWN"),
    )
    EvidenceEngine().evaluate(v)
    assert v.evidence.level == "E5"


def test_downgrade_records_reason():
    v = _vuln(
        sink=SinkInfo(type="execute"),
        source=SourceInfo(type="http_query"),
        data_flow=[DataFlowStep(step="x")],
        reachability=ReachabilityInfo(status="REACHABLE"),
        sanitizer=SanitizerInfo(present="NO"),
        authorization=AuthInfo(required="YES", status="MISSING"),
        verification=VerificationInfo(method="poc.py", result="success"),
        impact=ImpactInfo(confidentiality="CRITICAL"),
    )
    EvidenceEngine().evaluate(v)
    assert v.evidence.level == "E5"

    # Verification evidence evaporates.
    v.verification = VerificationInfo()
    EvidenceEngine().evaluate(v)
    assert v.evidence.level == "E3"
    assert "downgrade" in v.evidence.proof.lower()
