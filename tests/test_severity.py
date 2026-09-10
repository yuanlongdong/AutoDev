"""Tests for vulnresearch.severity (PHASE 23)."""
from __future__ import annotations

from vulnresearch.models import (
    ReachabilityInfo,
    SinkInfo,
    SourceInfo,
    Vulnerability,
)
from vulnresearch.severity import ImpactScorer, SeverityEngine


def _vuln(**kw) -> Vulnerability:
    base = dict(id="V-1", title="t", category="sql-injection", severity="Medium")
    base.update(kw)
    return Vulnerability(**base)


def test_band_boundaries():
    band = SeverityEngine._band
    assert band(14) == "Critical"
    assert band(20) == "Critical"
    assert band(13) == "High"
    assert band(10) == "High"
    assert band(9) == "Medium"
    assert band(6) == "Medium"
    assert band(5) == "Low"
    assert band(3) == "Low"
    assert band(2) == "Info"
    assert band(0) == "Info"


def test_default_impact_from_category():
    scorer = ImpactScorer("command-injection")
    impact = scorer.default_impact()
    assert impact["confidentiality"] == "CRITICAL"
    assert impact["integrity"] == "CRITICAL"

    scorer_low = ImpactScorer("open-redirect")
    assert scorer_low.default_impact()["confidentiality"] == "LOW"


def test_rate_critical_end_to_end():
    v = _vuln(
        severity="Unknown",
        category="command-injection",
        sink=SinkInfo(type="os.system"),
        source=SourceInfo(type="http_query"),
        data_flow=[],
        reachability=ReachabilityInfo(status="REACHABLE"),
    )
    # command-injection default impact 9 + exploitability 1 (sink, no flow)
    # + privilege 1 + user-interaction 0 + reachability 3 + scope 0 = 14
    assert SeverityEngine().rate(v) == "Critical"
    # impact was materialised from the category default
    assert v.impact.confidentiality == "CRITICAL"


def test_preserve_existing_severity_by_default():
    v = _vuln(severity="Low")
    assert SeverityEngine().rate(v) == "Low"


def test_force_overrides_existing_severity():
    v = _vuln(
        severity="Low",
        category="command-injection",
        sink=SinkInfo(type="os.system"),
        reachability=ReachabilityInfo(status="REACHABLE"),
    )
    rated = SeverityEngine().rate(v, force=True)
    assert rated == "Critical"
