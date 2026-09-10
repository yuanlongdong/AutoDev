"""v0.3.0 – round-3 targeted detector tests.

Each detector gets at least one positive (vulnerable fixture) and one
negative (safe fixture / false-positive guard) test.  Fixtures live under
``tests/fixtures/round3/`` and mirror the confirmed shooting-range patterns.
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.detectors import (
    IDORDetector,
    SecurityMisconfigurationDetector,
    SensitiveDataLoggingDetector,
    UserEnumerationDetector,
    SensitiveDataExposureDetector,
    MissingRateLimitingDetector,
    WeakPasswordPolicyDetector,
    BusinessLogicFlawDetector,
    RaceConditionDetector,
)

FIXTURES = Path(__file__).parent / "fixtures" / "round3"


def _detect(fixture: str, detector_cls):
    """Run *detector_cls* over every function in the fixture file."""
    p = FIXTURES / fixture
    ir = extract_python(p)
    lines = p.read_text(encoding="utf-8").splitlines()
    out = []
    for fn in ir.functions:
        out.extend(detector_cls().detect(fn, lines, ir))
    return out


# ---------------------------------------------------------------------------
# IDOR
# ---------------------------------------------------------------------------


def test_idor_detected_no_authz():
    r = _detect("idor_vuln.py", IDORDetector)
    idors = [v for v in r if v.category == "idor"]
    names = {v.function for v in idors}
    assert "user_profile" in names
    assert "view_document" in names
    assert all(v.severity == "High" for v in idors)


def test_idor_not_reported_with_authz():
    r = _detect("idor_vuln.py", IDORDetector)
    names = {v.function for v in r}
    # safe_profile uses session ownership; owned_order uses is_owner(current_user)
    assert "safe_profile" not in names
    assert "owned_order" not in names


def test_safe_functions_no_idor():
    r = _detect("safe_functions.py", IDORDetector)
    assert r == [], f"safe functions must not be reported: {[(v.category, v.function) for v in r]}"


# ---------------------------------------------------------------------------
# Privilege escalation
# ---------------------------------------------------------------------------


def test_privilege_escalation_delete_detected():
    r = _detect("priv_esc_vuln.py", IDORDetector)
    pe = [v for v in r if v.category == "privilege-escalation"]
    assert any(v.function == "delete_user" for v in pe)
    assert all(v.severity == "Critical" for v in pe)
    # the admin-guarded handler must stay silent
    names = {v.function for v in r}
    assert "admin_delete" not in names


# ---------------------------------------------------------------------------
# Security misconfiguration
# ---------------------------------------------------------------------------


def test_debug_mode_detected():
    r = _detect("misconfig_vuln.py", SecurityMisconfigurationDetector)
    assert r, "expected an app.run(debug=True) finding"
    assert any("debug=True" in v.evidence.proof for v in r)
    assert all(v.category == "security-misconfiguration" for v in r)


def test_insecure_bind_detected():
    r = _detect("misconfig_vuln.py", SecurityMisconfigurationDetector)
    assert any("0.0.0.0" in v.evidence.proof for v in r)
    # the app.run line itself is reported (not the DEBUG = True decoys)
    app_run = [v for v in r if "app.run(" in v.snippet]
    assert app_run, [v.snippet for v in r]


# ---------------------------------------------------------------------------
# Sensitive data in logs
# ---------------------------------------------------------------------------


def test_sensitive_logging_detected():
    r = _detect("logging_vuln.py", SensitiveDataLoggingDetector)
    assert any(v.function == "login" for v in r)
    # the safe audit handler logs only a username
    assert not any(v.function == "audit" for v in r)


# ---------------------------------------------------------------------------
# User enumeration
# ---------------------------------------------------------------------------


def test_user_enumeration_detected():
    r = _detect("user_enum_vuln.py", UserEnumerationDetector)
    names = {v.function for v in r}
    assert "brute_force_login" in names
    # generic-message login is not an enumeration vector
    assert "safe_login" not in names


# ---------------------------------------------------------------------------
# Sensitive data exposure
# ---------------------------------------------------------------------------


def test_sensitive_data_exposure_detected():
    r = _detect("sensitive_exposure.py", SensitiveDataExposureDetector)
    assert any(v.function == "store_sensitive" for v in r)
    assert all(v.severity == "High" for v in r)
    # the one-way-reference variant must not be flagged
    assert not any(v.function == "safe_store" for v in r)


# ---------------------------------------------------------------------------
# Missing rate limiting
# ---------------------------------------------------------------------------


def test_missing_rate_limiting_detected():
    r = _detect("user_enum_vuln.py", MissingRateLimitingDetector)
    assert any(v.function == "brute_force_login" for v in r)


# ---------------------------------------------------------------------------
# Weak password policy
# ---------------------------------------------------------------------------


def test_weak_password_policy_detected():
    r = _detect("weak_password.py", WeakPasswordPolicyDetector)
    assert any(v.function == "change_password" for v in r)


def test_weak_password_not_reported_with_complexity():
    r = _detect("weak_password.py", WeakPasswordPolicyDetector)
    names = {v.function for v in r}
    # signup enforces length + regex complexity → safe
    assert "signup" not in names


# ---------------------------------------------------------------------------
# Business logic flaw
# ---------------------------------------------------------------------------


def test_business_logic_negative_amount_detected():
    r = _detect("business_logic.py", BusinessLogicFlawDetector)
    assert any(v.function == "transfer_funds" for v in r)
    # safe_transfer rejects amount <= 0 → not flagged
    assert not any(v.function == "safe_transfer" for v in r)


# ---------------------------------------------------------------------------
# Race condition placeholder
# ---------------------------------------------------------------------------


def test_race_condition_placeholder_exists():
    assert hasattr(RaceConditionDetector, "detect")
    p = FIXTURES / "business_logic.py"
    ir = extract_python(p)
    lines = p.read_text(encoding="utf-8").splitlines()
    for fn in ir.functions:
        # the placeholder intentionally never reports anything
        assert RaceConditionDetector().detect(fn, lines, ir) == []
