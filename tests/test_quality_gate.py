"""Tests for vulnresearch.quality_gate (PHASE 28)."""
from __future__ import annotations

from vulnresearch.models import (
    AuthInfo,
    DataFlowStep,
    EvidenceInfo,
    ImpactInfo,
    ReachabilityInfo,
    SanitizerInfo,
    SinkInfo,
    SourceInfo,
    VerificationInfo,
    Vulnerability,
)
from vulnresearch.quality_gate import QualityCheck, QualityGate, QualityGateResult


def _ready_vuln(**over) -> Vulnerability:
    """A finding that should pass every one of the 16 checks."""
    base = dict(
        id="V-OK", title="ready", category="sql-injection", severity="High",
        status="potential", confidence="High",
        file="app.py", line=10, function="view",
        source=SourceInfo(type="http_query"),
        data_flow=[DataFlowStep(step="tainted", location="app.py:9")],
        sanitizer=SanitizerInfo(present="NO"),
        authentication=AuthInfo(required="NO"),
        authorization=AuthInfo(required="NO", status="MISSING"),
        reachability=ReachabilityInfo(status="REACHABLE"),
        sink=SinkInfo(type="sql", location="app.py:10"),
        impact=ImpactInfo(confidentiality="HIGH", integrity="HIGH",
                          availability="MEDIUM", privilege="LOW"),
        evidence=EvidenceInfo(level="E3", proof="proven"),
        root_cause="共享查询构造器允许未参数化字符串拼接",
        variants=["app.py:20"],
        vulnerability_family="FAM-001",
        verification=VerificationInfo(environment="unit", method="poc",
                                      result="success"),
        remediation="Use parameterised queries.",
    )
    base.update(over)
    return Vulnerability(**base)


def test_all_16_checks_run():
    result = QualityGate().check(_ready_vuln())
    assert len(result.checks) == 16
    names = [c.name for c in result.checks]
    # the PHASE 28 checklist names
    for expected in (
        "scope_confirmed", "source_confirmed", "sink_confirmed",
        "data_flow_confirmed", "reachability_confirmed",
        "authentication_analyzed", "authorization_analyzed",
        "sanitizer_analyzed", "impact_analyzed", "evidence_graded",
        "confidence_rated", "root_cause_extracted", "variant_analysis_done",
        "duplicate_checked", "poc_non_destructive", "remediation_clear",
    ):
        assert expected in names


def test_fully_populated_finding_passes():
    result = QualityGate().check(_ready_vuln())
    assert result.all_passed, [c for c in result.checks if not c.passed]
    assert result.failed_count == 0
    assert QualityGate().can_confirm(_ready_vuln()) is True


def test_bare_finding_fails_many_checks():
    v = Vulnerability(id="V-BARE", title="bare", category="x", severity="Low")
    result = QualityGate().check(v)
    assert result.all_passed is False
    assert result.failed_count >= 10  # most slots are UNKNOWN/empty
    # structural checks that must fail on a bare object
    failed = {c.name for c in result.checks if not c.passed}
    assert "scope_confirmed" in failed
    assert "source_confirmed" in failed
    assert "root_cause_extracted" in failed
    assert "remediation_clear" in failed
    # dedup check is always guaranteed by the engine
    assert "duplicate_checked" not in failed


def test_data_flow_via_evidence_level_e2():
    """Check 4 passes either via data_flow OR evidence level >= E2."""
    v = _ready_vuln(data_flow=[])  # no hops, but E3 evidence
    result = QualityGate().check(v)
    df_check = next(c for c in result.checks if c.name == "data_flow_confirmed")
    assert df_check.passed


def test_production_poc_is_rejected():
    v = _ready_vuln(verification=VerificationInfo(environment="production"))
    result = QualityGate().check(v)
    poc = next(c for c in result.checks if c.name == "poc_non_destructive")
    assert not poc.passed


def test_apply_gate_promotes_when_all_pass():
    gate = QualityGate()
    v = _ready_vuln(status="likely")
    gate.apply_gate(v)
    assert v.status == "confirmed"


def test_apply_gate_blocks_confirmation_when_failing():
    gate = QualityGate()
    v = Vulnerability(id="V-X", title="x", category="x", severity="Low",
                      status="confirmed")  # premature confirmation
    gate.apply_gate(v)
    assert v.status == "likely"           # demoted, never confirmed
    assert gate.can_confirm(v) is False


def test_result_dataclass_helpers():
    res = QualityGateResult(checks=[
        QualityCheck(name="a", passed=True),
        QualityCheck(name="b", passed=False),
        QualityCheck(name="c", passed=False),
    ])
    assert res.all_passed is False
    assert res.failed_count == 2
