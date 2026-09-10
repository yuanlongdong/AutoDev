"""Tests for vulnresearch.variant_analyzer (PHASE 8)."""
from __future__ import annotations

from vulnresearch.ir import ProjectIR
from vulnresearch.models import (
    DataFlowStep,
    EvidenceInfo,
    SinkInfo,
    SourceInfo,
    Vulnerability,
)
from vulnresearch.root_cause import MISSING_INPUT_VALIDATION, RootCauseAnalyzer
from vulnresearch.variant_analyzer import VariantAnalyzer


def _vuln(
    id_: str,
    category: str,
    sink_type: str,
    file: str,
    line: int,
    **kw,
) -> Vulnerability:
    base = dict(
        id=id_,
        title=category,
        category=category,
        severity="High",
        file=file,
        line=line,
        function=f"fn_{id_}",
        snippet=f"{sink_type}({file}:{line})",
        sink=SinkInfo(type=sink_type, location=f"{file}:{line}"),
        evidence=EvidenceInfo(level="E1", proof="x"),
    )
    base.update(kw)
    return Vulnerability(**base)


def test_same_sink_function_variant_found():
    seed = _vuln("v1", "command-injection", "command", "a.py", 10)
    sibling = _vuln("v2", "command-injection", "command", "b.py", 40)
    unrelated = _vuln("v3", "xss", "browser", "c.py", 5)

    out = VariantAnalyzer().find_variants(
        seed, ProjectIR(), [seed, sibling, unrelated]
    )
    ids = {v.id for v in out}
    assert "v2" in ids          # same dangerous sink family
    assert "v3" not in ids      # different sink family
    assert "v1" not in ids      # the seed itself is never returned


def test_variant_uses_same_data_flow_dimension():
    seed = _vuln(
        "v1", "sql-injection", "sql", "a.py", 10,
        source=SourceInfo(type="http_query"),
        data_flow=[DataFlowStep(step="x")],
    )
    twin = _vuln(
        "v2", "sql-injection", "sql", "b.py", 22,
        source=SourceInfo(type="http_query"),
        data_flow=[DataFlowStep(step="y")],
    )
    other_sink = _vuln("v3", "ssrf", "network", "c.py", 7,
                       source=SourceInfo(type="http_query"))

    out = VariantAnalyzer().find_variants(
        seed, ProjectIR(), [seed, twin, other_sink]
    )
    assert {v.id for v in out} == {"v2"}


def test_cluster_by_root_cause_groups():
    v1 = _vuln("v1", "sql-injection", "sql", "a.py", 10)
    v2 = _vuln("v2", "command-injection", "command", "a.py", 20)
    v3 = _vuln("v3", "ssrf", "network", "b.py", 5)

    clusters = VariantAnalyzer().cluster_by_root_cause([v1, v2, v3])
    assert set(clusters) >= {MISSING_INPUT_VALIDATION, "trust_boundary_violation"}
    assert len(clusters[MISSING_INPUT_VALIDATION]) == 2
    assert len(clusters["trust_boundary_violation"]) == 1


def test_build_families_structure():
    v1 = _vuln("v1", "sql-injection", "sql", "app.py", 10)
    v2 = _vuln("v2", "sql-injection", "sql", "app.py", 30)
    v3 = _vuln("v3", "ssrf", "network", "net.py", 5)

    families = VariantAnalyzer().build_families([v1, v2, v3], ProjectIR())
    assert len(families) >= 1

    injection_family = next(
        f for f in families
        if f.root_cause.category == MISSING_INPUT_VALIDATION
    )
    assert injection_family.family_id
    assert len(injection_family.variants) == 2
    # both findings live in app.py -> shared component
    assert injection_family.shared_component.endswith("app.py")
    assert injection_family.affected_entrypoints


def test_find_variants_dedup_by_category_file_line():
    seed = _vuln("v1", "command-injection", "command", "a.py", 10)
    dup = _vuln("v1-dup", "command-injection", "command", "a.py", 10)
    out = VariantAnalyzer().find_variants(
        seed, ProjectIR(), [seed, dup]
    )
    # same (category, file, line) as seed -> excluded entirely
    assert out == []


def test_root_cause_analyzer_is_injectable():
    rc = RootCauseAnalyzer()
    va = VariantAnalyzer(rc)
    assert va.rc is rc
