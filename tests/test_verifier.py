"""Tests for vulnresearch.verifier (PHASE 13)."""
from __future__ import annotations

from vulnresearch.models import DataFlowStep
from vulnresearch.verifier import Verifier, VerificationResult

from conftest import make_vuln


def _proven_vuln():
    return make_vuln(
        id="VP1",
        source_type="http_query",
        data_flow=[
            DataFlowStep(step="read", location="app.py:3", transformation="request.args"),
            DataFlowStep(step="use", location="app.py:5", transformation="query"),
        ],
        reachability="REACHABLE",
        evidence_level="E2",
    )


def test_static_proof_confirmed():
    v = _proven_vuln()
    verifier = Verifier()
    assert verifier.static_proof(v) is True
    result = verifier.verify(v)
    assert isinstance(result, VerificationResult)
    assert result.environment == "static"
    assert result.result == "confirmed"
    assert result.non_destructive is True


def test_static_proof_rejected_when_no_data_flow():
    v = make_vuln(id="VP2", source_type="http_query", reachability="REACHABLE")
    verifier = Verifier()
    assert verifier.static_proof(v) is False
    # falls through to unit-test lookup stage (still non-destructive)
    result = verifier.verify(v)
    assert result.environment in {"unit", "integration", "docker"}
    assert result.non_destructive is True


def test_verification_priority_order():
    priority = Verifier().verification_priority()
    assert priority == ["static", "unit", "integration", "docker", "authorized"]


def test_find_regression_test_suggestion():
    v = make_vuln(id="VP3", category="xss")
    text = Verifier().find_regression_test(v)
    assert "test_regression_xss" in text
    assert "```python" in text


def test_all_results_are_non_destructive():
    v = make_vuln(id="VP4")
    for _ in range(1):
        result = Verifier().verify(v)
        assert result.non_destructive is True
