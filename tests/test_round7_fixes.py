"""v0.4.2 – round-7 shooting-range detector tests.

Covers the four round-7 misses:
  * CORS Misconfiguration (user-controlled origin / wildcard+credentials)
  * Insecure Cookie attributes (missing httponly / secure)
  * Zip Slip / unsafe archive extraction of user uploads
  * CodeInjectionDetector recognising Django-style request.POST / request.GET

Each new rule gets a positive assertion and (where applicable) a negative
assertion.  Two integration tests re-scan the real shooting-range targets to
prove the new findings survive the full legacy + structured pipeline.
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.detectors import (
    CORSMisconfigurationDetector,
    InsecureCookieDetector,
    ZipSlipDetector,
    CodeInjectionDetector,
    scan_file_with_ir,
)

FIXTURES = Path(__file__).parent / "fixtures" / "round7"
# tests/ -> AutoDev/ -> 38441101299106050/
SHOOTING_RANGE = Path(__file__).resolve().parents[2] / "shooting_range"


def _detect(fixture: str, detector_cls):
    p = FIXTURES / fixture
    ir = extract_python(p)
    lines = p.read_text(encoding="utf-8").splitlines()
    out = []
    for fn in ir.functions:
        out.extend(detector_cls().detect(fn, lines, ir))
    return out


def _by_cat(findings, category):
    return [v for v in findings if v.category == category]


# ---------------------------------------------------------------------------
# A. CORS Misconfiguration
# ---------------------------------------------------------------------------


def test_cors_user_controlled_origin_detected():
    r = _detect("cors_vuln.py", CORSMisconfigurationDetector)
    cors = _by_cat(r, "cors-misconfiguration")
    assert any(v.function == "cors_reflect_origin" for v in cors), r
    assert any("Access-Control-Allow-Origin" in v.snippet for v in cors)


def test_cors_static_origin_not_reported():
    r = _detect("cors_vuln.py", CORSMisconfigurationDetector)
    cors = _by_cat(r, "cors-misconfiguration")
    # The fixed trusted-domain origin must never be flagged.
    assert all(v.function != "cors_static_origin" for v in cors)


def test_cors_wildcard_with_credentials_detected():
    r = _detect("cors_vuln.py", CORSMisconfigurationDetector)
    cors = _by_cat(r, "cors-misconfiguration")
    assert any(v.function == "cors_wildcard_with_creds" for v in cors)


def test_cors_flask_cors_wildcard_detected():
    r = _detect("cors_vuln.py", CORSMisconfigurationDetector)
    cors = _by_cat(r, "cors-misconfiguration")
    assert any(v.function == "configure_cors" for v in cors)


# ---------------------------------------------------------------------------
# B. Insecure Cookie
# ---------------------------------------------------------------------------


def test_insecure_cookie_httponly_false_detected():
    r = _detect("insecure_cookie.py", InsecureCookieDetector)
    ck = _by_cat(r, "insecure-cookie")
    funcs = {v.function for v in ck}
    assert "bad_cookie_explicit_flags" in funcs
    assert "bad_cookie_missing_flags" in funcs
    assert "django_style_bad" in funcs


def test_insecure_cookie_secure_flags_not_reported():
    r = _detect("insecure_cookie.py", InsecureCookieDetector)
    ck = _by_cat(r, "insecure-cookie")
    # Explicit httponly=True + secure=True is safe and must not be reported.
    assert all(v.function != "good_cookie_flags" for v in ck)
    # severity comes from the knowledge base (Low / CWE-614)
    assert all(v.severity == "Low" for v in ck)


# ---------------------------------------------------------------------------
# C. Zip Slip
# ---------------------------------------------------------------------------


def test_zip_slip_extractall_detected():
    r = _detect("zip_slip.py", ZipSlipDetector)
    zs = _by_cat(r, "zip-slip")
    assert any(v.function == "unsafe_extract_zip" for v in zs)
    assert any("extractall" in v.snippet for v in zs)
    assert all(v.severity == "High" for v in zs)


def test_zip_slip_with_validation_not_reported():
    r = _detect("zip_slip.py", ZipSlipDetector)
    zs = _by_cat(r, "zip-slip")
    # The validated safe variant (infolist + '..' check) must be skipped.
    assert all(v.function != "safe_extract_zip" for v in zs)


# ---------------------------------------------------------------------------
# D. Django-style request.POST / request.GET code injection
# ---------------------------------------------------------------------------


def test_django_post_eval_detected():
    r = _detect("django_eval.py", CodeInjectionDetector)
    ci = _by_cat(r, "code-injection")
    assert any(v.function == "calculate" for v in ci)
    assert any(v.function == "dynamic_query" for v in ci)


def test_django_get_eval_detected():
    r = _detect("django_eval.py", CodeInjectionDetector)
    ci = _by_cat(r, "code-injection")
    assert any(v.function == "evaluate_query_param" for v in ci)


# ---------------------------------------------------------------------------
# E. Integration: real shooting-range targets
# ---------------------------------------------------------------------------


def test_code_injection_django_target1_detected():
    api = SHOOTING_RANGE / "django-target1" / "api.py"
    if not api.exists():
        import pytest
        pytest.skip(f"shooting range not found: {api}")
    ir = extract_python(api)
    findings = scan_file_with_ir(api, ir)
    ci = [v for v in findings if v.category == "code-injection"]
    # eval (L262) + exec (L272) both survive the full pipeline.
    assert len(ci) >= 2, f"expected >=2 code-injection findings, got {len(ci)}"


def test_cors_in_sast_target_detected():
    app = SHOOTING_RANGE / "sast-target" / "app.py"
    if not app.exists():
        import pytest
        pytest.skip(f"shooting range not found: {app}")
    ir = extract_python(app)
    findings = scan_file_with_ir(app, ir)
    cors = [v for v in findings if v.category == "cors-misconfiguration"]
    assert len(cors) >= 1, "expected >=1 cors-misconfiguration finding in sast-target"
    ck = [v for v in findings if v.category == "insecure-cookie"]
    assert len(ck) >= 1, "expected >=1 insecure-cookie finding in sast-target"
