"""v0.4.4 – round-9 shooting-range detector tests.

Covers the round-9 miss: the **two-step XSS** pattern where HTML is built in a
separate statement and only *then* returned::

    message = request.GET.get('msg', '')
    html = f"<div class='message'>{message}</div>"   # f-string HTML assigned to a var
    return HttpResponse(html)                        # ...and the var reaches a sink

The v0.4.3 XSSDetector only flagged ``return f"<html>{v}</html>"`` directly on
the return line; it missed this shape — and, specifically, could not see
through single-quoted HTML attributes (``class='message'``) with its line regex.
The fix adds an AST-aware two-step pass gated on the existing taint model.

Positive and negative unit tests cover the fixtures, plus one integration test
that re-scans the real ``django-target1`` to prove the new finding survives the
full legacy + structured pipeline.
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.detectors import XSSDetector, scan_file_with_ir

FIXTURES = Path(__file__).parent / "fixtures" / "round9"
# tests/ -> AutoDev/ -> 38441101299106050/
SHOOTING_RANGE = Path(__file__).resolve().parents[2] / "shooting_range"


def _detect(fixture: str):
    p = FIXTURES / fixture
    ir = extract_python(p)
    lines = p.read_text(encoding="utf-8").splitlines()
    out = []
    for fn in ir.functions:
        out.extend(XSSDetector().detect(fn, lines, ir))
    return [v for v in out if v.category == "xss"]


# ---------------------------------------------------------------------------
# True positive — two-step assignment + return
# ---------------------------------------------------------------------------


def test_xss_two_step_detected():
    findings = _detect("xss_two_step.py")
    # format_message: html = f"<div class='message'>{message}</div>" ; HttpResponse(html)
    assert any(v.function == "format_message" for v in findings), findings
    # bare_return: html = f"<p>{q}</p>" ; return html
    assert any(v.function == "bare_return" for v in findings), findings


def test_xss_two_step_reports_assignment_line():
    findings = _detect("xss_two_step.py")
    fm = [v for v in findings if v.function == "format_message"]
    assert len(fm) == 1, fm
    # the finding lives on the f-string assignment, not the return
    assert "f\"<div class='message'>" in fm[0].snippet, fm[0].snippet


# ---------------------------------------------------------------------------
# False positives — must NOT be reported
# ---------------------------------------------------------------------------


def test_xss_two_step_db_output_not_reported():
    findings = _detect("xss_two_step_safe.py")
    assert not findings, f"database output leaked as XSS: {[(v.line, v.snippet) for v in findings]}"


def test_xss_two_step_static_not_reported():
    findings = _detect("xss_two_step_static.py")
    assert not findings, f"static HTML leaked as XSS: {[(v.line, v.snippet) for v in findings]}"


# ---------------------------------------------------------------------------
# Integration — real shooting-range target
# ---------------------------------------------------------------------------


def test_xss_two_step_django_target1_detected():
    views = SHOOTING_RANGE / "django-target1" / "views.py"
    if not views.exists():
        import pytest
        pytest.skip(f"shooting range not found: {views}")
    ir = extract_python(views)
    findings = scan_file_with_ir(views, ir)
    xs = [v for v in findings if v.category == "xss"]
    # round-8 already found 2 (greet_user L109, render_profile L117); the two-step
    # fix must add format_message (L125) → at least 3 XSS findings.
    assert len(xs) >= 3, f"expected >=3 XSS in django-target1, got {len(xs)}: {[(v.line, v.snippet) for v in xs]}"
    assert any(v.function == "format_message" for v in xs), xs
