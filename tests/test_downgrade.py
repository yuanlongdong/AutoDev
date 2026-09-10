"""Tests for vulnresearch.downgrade (PHASE 19)."""
from __future__ import annotations

from vulnresearch.downgrade import DowngradeEngine
from vulnresearch.models import (
    AuthInfo,
    ReachabilityInfo,
    SanitizerInfo,
    Vulnerability,
)


def _clean_vuln(**kw) -> Vulnerability:
    """A vulnerability with *no* downgrade signals by default."""
    base = dict(
        id="V-1", title="t", category="sql-injection", severity="High",
        confidence="High", status="confirmed",
        file="app.py",
        sanitizer=SanitizerInfo(present="NO"),
        authorization=AuthInfo(required="NO", status="PRESENT"),
        reachability=ReachabilityInfo(status="REACHABLE"),
    )
    base.update(kw)
    return Vulnerability(**base)


def test_no_trigger_on_clean_vuln():
    assert DowngradeEngine().check(_clean_vuln(), {}) == []


def test_unknown_sanitizer_rule():
    v = _clean_vuln(sanitizer=SanitizerInfo(present="UNKNOWN"))
    reasons = DowngradeEngine().check(v, {})
    assert any("sanitizer" in r.lower() for r in reasons)


def test_unknown_authorization_rule():
    v = _clean_vuln(authorization=AuthInfo(required="UNKNOWN"))
    reasons = DowngradeEngine().check(v, {})
    assert any("authorization" in r.lower() for r in reasons)


def test_unknown_reachability_rule():
    v = _clean_vuln(reachability=ReachabilityInfo(status="UNKNOWN"))
    reasons = DowngradeEngine().check(v, {})
    assert any("reachability" in r.lower() for r in reasons)


def test_dead_code_rule():
    reasons = DowngradeEngine().check(_clean_vuln(), {"dead_code": True})
    assert any("dead code" in r.lower() for r in reasons)


def test_unreachable_branch_rule():
    v = _clean_vuln(reachability=ReachabilityInfo(status="UNREACHABLE"))
    reasons = DowngradeEngine().check(v, {})
    assert any("unreachable" in r.lower() for r in reasons)


def test_feature_disabled_rule():
    reasons = DowngradeEngine().check(_clean_vuln(), {"feature_enabled": False})
    assert any("disabled" in r.lower() for r in reasons)


def test_dependency_not_reachable_rule():
    reasons = DowngradeEngine().check(_clean_vuln(), {"dependency_reachable": False})
    assert any("dependency" in r.lower() for r in reasons)


def test_false_positive_pattern_rule():
    reasons = DowngradeEngine().check(_clean_vuln(), {"false_positive_pattern": True})
    assert any("false-positive" in r.lower() for r in reasons)


def test_test_only_code_detection():
    for path in ("tests/test_app.py", "app/test_views.py", "app/conftest.py",
                 "app/utils/tests/helpers.py"):
        v = _clean_vuln(file=path)
        reasons = DowngradeEngine().check(v, {})
        assert any("test" in r.lower() for r in reasons), path


def test_apply_lowers_confidence_and_evidence():
    v = _clean_vuln()
    v.sanitizer.present = "UNKNOWN"  # one trigger
    out = DowngradeEngine().apply(v, {})
    assert out.confidence == "Medium"
    assert out.evidence.level == "E0"  # E1 - 1
    assert out.status == "potential"  # confirmed -> potential


def test_apply_caps_evidence_drop_at_two():
    v = _clean_vuln()
    # Fire several rules at once.
    v.sanitizer.present = "UNKNOWN"
    v.authorization.required = "UNKNOWN"
    v.reachability.status = "UNREACHABLE"
    v.evidence.level = "E4"
    DowngradeEngine().apply(v, {})
    assert v.evidence.level == "E2"  # E4 - 2, capped
