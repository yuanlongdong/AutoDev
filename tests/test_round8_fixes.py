"""v0.4.3 – round-8 shooting-range detector tests.

Covers the four round-8 misses:
  * Email Header Injection (smtplib + f-string To/Subject headers)
  * CodeInjectionDetector recognising ``self.<attr>`` (second-order eval/exec)
  * SSLVerificationDisablerDetector recognising paramiko.AutoAddPolicy()
  * Insecure Temporary File (predictable /tmp path + chmod 0o777)

Each rule gets a positive assertion and (where applicable) a negative
assertion.  Two integration tests re-scan the real shooting-range targets to
prove the new findings survive the full legacy + structured pipeline.
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.detectors import (
    EmailHeaderInjectionDetector,
    InsecureTempFileDetector,
    CodeInjectionDetector,
    SSLVerificationDisablerDetector,
    scan_file_with_ir,
)

FIXTURES = Path(__file__).parent / "fixtures" / "round8"
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
# A. Email Header Injection
# ---------------------------------------------------------------------------


def test_email_header_injection_detected():
    r = _detect("email_injection.py", EmailHeaderInjectionDetector)
    em = _by_cat(r, "email-header-injection")
    assert any(v.function == "send_email" for v in em), r
    # severity comes from the knowledge base (Medium / CWE-640)
    assert all(v.severity == "Medium" for v in em)


def test_email_without_user_input_not_reported():
    r = _detect("email_injection.py", EmailHeaderInjectionDetector)
    em = _by_cat(r, "email-header-injection")
    # The static, non-interpolated message body must never be flagged.
    assert all(v.function != "send_email_safe" for v in em)


# ---------------------------------------------------------------------------
# B. Second-order code execution: eval/exec on self.<attr>
# ---------------------------------------------------------------------------


def test_eval_self_attribute_detected():
    r = _detect("model_eval.py", CodeInjectionDetector)
    ci = _by_cat(r, "code-injection")
    funcs = {v.function for v in ci}
    assert "evaluate" in funcs          # eval(self.expression)
    assert "execute" in funcs          # exec(self.code)
    assert "compile_it" in funcs       # compile(self.expression)


def test_eval_static_literal_not_reported():
    r = _detect("model_eval.py", CodeInjectionDetector)
    ci = _by_cat(r, "code-injection")
    # eval("1 + 1") / exec("print('hi')") are static literals → safe.
    assert all(v.function not in {"literal", "trusted"} for v in ci)


# ---------------------------------------------------------------------------
# C. SSH AutoAddPolicy (folded into ssl-verification-disabled)
# ---------------------------------------------------------------------------


def test_ssh_autoadd_policy_detected():
    r = _detect("ssh_autoadd.py", SSLVerificationDisablerDetector)
    ssl = _by_cat(r, "ssl-verification-disabled")
    assert any(v.function == "connect_ssh_insecure" for v in ssl), r
    assert any("AutoAddPolicy" in v.snippet for v in ssl)


def test_ssh_reject_policy_not_reported():
    r = _detect("ssh_autoadd.py", SSLVerificationDisablerDetector)
    ssl = _by_cat(r, "ssl-verification-disabled")
    # RejectPolicy() is the safe default → must not be flagged.
    assert all(v.function != "connect_ssh_safe" for v in ssl)


# ---------------------------------------------------------------------------
# D. Insecure Temporary File
# ---------------------------------------------------------------------------


def test_insecure_temp_predictable_path_detected():
    r = _detect("insecure_temp.py", InsecureTempFileDetector)
    tf = _by_cat(r, "insecure-temp-file")
    assert any(v.function == "create_predictable_temp" for v in tf), r
    # severity comes from the knowledge base (Low)
    assert all(v.severity == "Low" for v in tf)


def test_insecure_temp_chmod_777_detected():
    r = _detect("insecure_temp.py", InsecureTempFileDetector)
    tf = _by_cat(r, "insecure-temp-file")
    assert any(v.function == "create_shared_temp" for v in tf), r


def test_tempfile_mkstemp_not_reported():
    r = _detect("insecure_temp.py", InsecureTempFileDetector)
    tf = _by_cat(r, "insecure-temp-file")
    # tempfile.mkstemp() is the secure API → must not be flagged.
    assert all(v.function != "create_temp_safe" for v in tf)


# ---------------------------------------------------------------------------
# E. Integration: real shooting-range target
# ---------------------------------------------------------------------------


def test_round8_findings_in_django_target1():
    api = SHOOTING_RANGE / "django-target1" / "api.py"
    if not api.exists():
        import pytest
        pytest.skip(f"shooting range not found: {api}")
    ir = extract_python(api)
    findings = scan_file_with_ir(api, ir)
    em = [v for v in findings if v.category == "email-header-injection"]
    assert len(em) >= 1, "expected >=1 email-header-injection finding in django-target1"
    ssh = [v for v in findings if v.category == "ssl-verification-disabled"]
    assert any("AutoAddPolicy" in v.snippet for v in ssh), "expected SSH AutoAddPolicy finding"
