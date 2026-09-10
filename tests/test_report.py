"""Tests for vulnresearch.report (PHASE 27)."""
from __future__ import annotations

from vulnresearch.report import ReportGenerator, SECTION_TITLES
from vulnresearch.models import DataFlowStep

from conftest import make_vuln


REQUIRED_SECTIONS = [
    "1. Summary",
    "2. Severity",
    "3. Confidence",
    "4. Affected Component",
    "5. Root Cause",
    "6. Source",
    "7. Data Flow",
    "8. Authorization Analysis",
    "9. Sink",
    "10. Security Impact",
    "11. Safe Reproduction",
    "12. Evidence",
    "13. Vulnerability Variants",
    "14. Recommended Fix",
    "15. Regression Test",
]


def test_report_contains_all_fifteen_sections():
    vulns = [
        make_vuln(id="V1", category="sql-injection", status="confirmed",
                  confidence="High", evidence_level="E3"),
        make_vuln(id="V2", category="xss", severity="Medium", status="likely",
                  confidence="Medium", evidence_level="E2"),
    ]
    md = ReportGenerator().generate(vulns)
    assert len(SECTION_TITLES) == 15
    for section in REQUIRED_SECTIONS:
        assert f"## {section}" in md, f"missing section: {section}"


def test_report_distinguishes_statuses():
    vulns = [
        make_vuln(id="V1", status="confirmed"),
        make_vuln(id="V2", status="likely"),
        make_vuln(id="V3", status="potential"),
        make_vuln(id="V4", status="rejected"),
    ]
    md = ReportGenerator().generate(vulns)
    for label in ("Confirmed", "Likely", "Potential", "Rejected"):
        assert label in md


def test_empty_vuln_list_handled():
    md = ReportGenerator().generate([])
    assert "Total vulnerabilities:** 0" in md
    # every section header still present for a stable skeleton
    for section in REQUIRED_SECTIONS:
        assert f"## {section}" in md


def test_single_vulnerability_report():
    vuln = make_vuln(
        id="V9", category="command-injection", severity="Critical",
        data_flow=[
            DataFlowStep(step="read", location="app.py:3", transformation="request.args"),
            DataFlowStep(step="call", location="app.py:5", transformation="os.system"),
        ],
    )
    single = ReportGenerator().generate_single(vuln)
    assert "V9" in single
    assert "command-injection" in single
    assert "Data Flow" in single
    assert "Code Snippet" in single
    assert "```" in single  # code block present


def test_report_uses_tables_and_code_blocks():
    vulns = [make_vuln()]
    md = ReportGenerator().generate(vulns)
    assert "| " in md          # markdown table
    assert "```" in md          # regression-test code block
