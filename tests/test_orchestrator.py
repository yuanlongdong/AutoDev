"""End-to-end tests for vulnresearch.orchestrator (PHASE 24).

Runs the whole research loop over the intentionally-vulnerable sample
application under ``tests/fixtures/vulnerable_app`` and checks that the result
bundle is structurally complete and that findings are actually classified.
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.asset_analyzer import AttackSurface
from vulnresearch.orchestrator import Orchestrator
from vulnresearch.root_cause import ROOT_CAUSE_CATEGORIES
from vulnresearch.chain_analyzer import VulnerabilityChain
from vulnresearch.variant_analyzer import VulnerabilityFamily


FIXTURE = Path(__file__).parent / "fixtures" / "vulnerable_app"

_EXPECTED_KEYS = {
    "vulnerabilities", "root_causes", "families", "chains",
    "attack_surface", "rejected", "stats",
}
_VALID_STATUSES = {"confirmed", "likely", "potential", "rejected"}


def _run() -> dict:
    return Orchestrator(str(FIXTURE)).run()


def test_end_to_end_runs_and_returns_full_structure():
    result = _run()
    assert set(result) == _EXPECTED_KEYS

    assert isinstance(result["vulnerabilities"], list)
    assert isinstance(result["rejected"], list)
    assert isinstance(result["root_causes"], list)
    assert isinstance(result["families"], list)
    assert isinstance(result["chains"], list)
    assert isinstance(result["attack_surface"], AttackSurface)
    assert isinstance(result["stats"], dict)

    for key in ("total", "by_status", "by_severity", "families", "chains",
                "rejected", "iterations"):
        assert key in result["stats"]


def test_vulnerabilities_are_classified():
    result = _run()
    vulns = result["vulnerabilities"] + result["rejected"]
    assert vulns, "the intentionally-vulnerable app must produce findings"

    categories = {v.category for v in vulns}
    # the fixture deliberately ships these flaw classes
    assert "sql-injection" in categories
    assert "command-injection" in categories
    assert "path-traversal" in categories
    assert "ssrf" in categories

    for v in vulns:
        assert v.category
        assert v.severity in {"Critical", "High", "Medium", "Low", "Info"}
        assert v.status in _VALID_STATUSES
        assert v.root_cause, f"{v.id} has no root cause attached"
        assert v.file


def test_root_causes_are_known_vocabulary():
    result = _run()
    assert result["root_causes"]
    for rc in result["root_causes"]:
        assert rc.category in ROOT_CAUSE_CATEGORIES
        assert rc.description
        assert rc.pattern is not None  # may be empty for "other", never None


def test_vulnerability_families_built():
    result = _run()
    assert result["families"], "repeat flaws must cluster into families"
    for fam in result["families"]:
        assert isinstance(fam, VulnerabilityFamily)
        assert fam.family_id
        assert fam.root_cause.category in ROOT_CAUSE_CATEGORIES
        assert fam.variants


def test_chains_detected_for_known_compositions():
    result = _run()
    # the fixture combines an unauthenticated admin route with a file-read
    # sink, which must fire the sensitive-data-exposure chain.
    assert result["chains"], "expected at least one composable chain"
    for chain in result["chains"]:
        assert isinstance(chain, VulnerabilityChain)
        assert chain.chain_id
        assert len(chain.steps) >= 2
        assert chain.combined_severity in {"Critical", "High", "Medium", "Low"}
        assert chain.description


def test_findings_are_deduplicated():
    result = _run()
    seen = set()
    for v in result["vulnerabilities"] + result["rejected"]:
        key = (v.category, v.file, v.line)
        assert key not in seen, f"duplicate finding: {key}"
        seen.add(key)


def test_attack_surface_enumerated():
    result = _run()
    surface = result["attack_surface"]
    assert surface.assets, "the fixture exposes HTTP handlers"
    assert surface.entry_points, "route handlers are entry points"


def test_stats_consistent():
    result = _run()
    s = result["stats"]
    assert s["total"] == len(result["vulnerabilities"]) + len(result["rejected"])
    assert sum(s["by_status"].values()) == s["total"]
    assert s["iterations"] >= 1
