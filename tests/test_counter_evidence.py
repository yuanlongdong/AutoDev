"""Tests for vulnresearch.counter_evidence (PHASE 21)."""
from __future__ import annotations

from vulnresearch.counter_evidence import CounterEvidenceEngine
from vulnresearch.models import (
    ReachabilityInfo,
    SinkInfo,
    Vulnerability,
)


def _vuln(**kw) -> Vulnerability:
    base = dict(id="V-1", title="t", category="sql-injection",
                severity="High", file="app.py",
                sink=SinkInfo(type="execute"),
                reachability=ReachabilityInfo(status="REACHABLE"))
    base.update(kw)
    return Vulnerability(**base)


def test_analyze_returns_all_checks():
    out = CounterEvidenceEngine().analyze(_vuln(), {})
    assert set(out) == {
        "hidden_sanitizer", "middleware_auth", "unified_authz",
        "service_layer_check", "unreachable_path", "disabled_config",
        "framework_auto_encoding", "orm_auto_parameterization",
    }
    for item in out.values():
        assert {"found", "description", "evidence_type"} <= set(item)


def test_hidden_sanitizer_updates_sanitizer_field():
    v = _vuln()
    ir = {"source_text": "safe = markupsafe.escape(request.args.get('q'))"}
    report = CounterEvidenceEngine().analyze(v, ir)
    assert report["hidden_sanitizer"]["found"] is True
    assert report["hidden_sanitizer"]["evidence_type"] == "evidence"

    CounterEvidenceEngine().apply_counter_evidence(v, ir)
    assert v.sanitizer.present == "YES"
    assert "escape" in v.sanitizer.description


def test_orm_auto_parameterization_found():
    v = _vuln(sink=SinkInfo(type="session.query.filter_by"))
    report = CounterEvidenceEngine().analyze(v, {})
    assert report["orm_auto_parameterization"]["found"] is True

    CounterEvidenceEngine().apply_counter_evidence(v, {})
    assert v.sanitizer.present == "YES"


def test_raw_sql_is_not_treated_as_orm():
    v = _vuln(sink=SinkInfo(type="db.execute"))
    report = CounterEvidenceEngine().analyze(v, {})
    assert report["orm_auto_parameterization"]["found"] is False


def test_no_counter_evidence_leaves_fields_untouched():
    v = _vuln()
    before_proof = v.evidence.proof
    report = CounterEvidenceEngine().analyze(v, {})
    assert report["hidden_sanitizer"]["found"] is False
    assert report["middleware_auth"]["found"] is False
    assert report["unified_authz"]["found"] is False

    CounterEvidenceEngine().apply_counter_evidence(v, {})
    assert v.sanitizer.present == "UNKNOWN"
    assert v.authentication.status == "UNKNOWN"
    assert v.evidence.proof == before_proof


def test_framework_detection_is_assumption():
    v = _vuln()
    ir = {"source_text": "from django.shortcuts import render"}
    report = CounterEvidenceEngine().analyze(v, ir)
    assert report["framework_auto_encoding"]["found"] is True
    assert report["framework_auto_encoding"]["evidence_type"] == "assumption"


def test_disabled_config_and_unreachable_are_reported():
    v = _vuln(reachability=ReachabilityInfo(status="UNREACHABLE"))
    ir = {"context": {"feature_enabled": False}}
    report = CounterEvidenceEngine().analyze(v, ir)
    assert report["unreachable_path"]["found"] is True
    assert report["disabled_config"]["found"] is True
