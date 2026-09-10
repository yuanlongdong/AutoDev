"""Tests for the extended vulnresearch.engine (PHASE 27)."""
from __future__ import annotations

from vulnresearch.engine import ResearchEngine
from vulnresearch.models import Finding, Vulnerability
from conftest import make_vuln


VULN_SRC = (
    "def view(user_id):\n"
    "    query = f\"SELECT * FROM users WHERE id={user_id}\"\n"
    "    db.execute(query)\n"
)


def _engine(tmp_path):
    return ResearchEngine(str(tmp_path))


def test_run_returns_list_of_findings(tmp_path):
    (tmp_path / "app.py").write_text(VULN_SRC, encoding="utf-8")
    findings = _engine(tmp_path).run()
    assert isinstance(findings, list)
    assert all(isinstance(f, Finding) for f in findings)


def test_run_vulnerabilities_returns_vulnerabilities(tmp_path):
    (tmp_path / "app.py").write_text(VULN_SRC, encoding="utf-8")
    vulns = _engine(tmp_path).run_vulnerabilities()
    assert isinstance(vulns, list)
    assert all(isinstance(v, Vulnerability) for v in vulns)


def test_run_deep_structure(tmp_path):
    (tmp_path / "app.py").write_text(VULN_SRC, encoding="utf-8")
    deep = _engine(tmp_path).run_deep()
    for key in ("vulnerabilities", "root_causes", "families", "chains",
                "attack_surface", "stats"):
        assert key in deep
    assert "total" in deep["stats"]


def test_build_ir(tmp_path):
    (tmp_path / "app.py").write_text(VULN_SRC, encoding="utf-8")
    ir = _engine(tmp_path).build_ir()
    assert hasattr(ir, "functions")
    assert any(fn.name == "view" for fn in ir.functions)


def test_build_attack_surface(tmp_path):
    (tmp_path / "app.py").write_text(VULN_SRC, encoding="utf-8")
    surface = _engine(tmp_path).build_attack_surface()
    assert hasattr(surface, "assets")


def test_deduplicate_by_root_cause():
    a = make_vuln(id="A", root_cause="unsanitized_user_input", severity="High")
    b = make_vuln(id="B", root_cause="unsanitized_user_input", severity="Low")
    c = make_vuln(id="C", root_cause="")  # orphan kept
    out = ResearchEngine.deduplicate_by_root_cause([a, b, c])
    ids = {v.id for v in out}
    # representative is highest severity: A survives, B folded away
    assert "A" in ids
    assert "B" not in ids
    assert "C" in ids


def test_deduplicate_legacy_unchanged():
    f1 = Finding(title="t", category="c", severity="High", confidence="Low",
                 evidence="e", path="p", line=1, snippet="s")
    f2 = Finding(title="t", category="c", severity="High", confidence="Low",
                 evidence="e", path="p", line=1, snippet="s")
    out = ResearchEngine.deduplicate([f1, f2])
    assert len(out) == 1
