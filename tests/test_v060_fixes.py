"""v0.6.0 — thirteenth hardening round.

New detectors and fixes:
* RaceConditionDetector — real TOCTOU / check-then-act heuristic (was a stub).
* MissingAuthenticationDetector — unauthenticated HTTP route handlers.
* SQL ``?`` parameterised queries with ``balance + ?`` arithmetic no longer
  flagged as SQL injection (substring ``" + "`` false positive).
* SSRF: env/config constant URLs (``BASE_URL`` / ``PRODUCT_SERVICE_URL``) and
  test/exploit client calls no longer flagged.
* ``taint_names`` fixpoint now terminates (whole-word matching + pass cap),
  fixing the vulnbank app.py 100 % CPU hang.
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.detectors import (
    RaceConditionDetector,
    MissingAuthenticationDetector,
    SQLInjectionDetector,
    SSRFDetector,
    taint_names,
)

FIXTURES = Path(__file__).parent / "fixtures" / "v060"


def _run_detector(detector, fixture: str):
    """Run *detector* over every function in the fixture file."""
    path = FIXTURES / fixture
    ir = extract_python(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    out = []
    for fn in ir.functions:
        out.extend(detector.detect(fn, lines, ir))
    return out


# ---------------------------------------------------------------------------
# 1. Race condition
# ---------------------------------------------------------------------------

def test_race_toctou_reported_on_withdraw():
    out = _run_detector(RaceConditionDetector(), "race_condition.py")
    names = {v.function for v in out if v.category == "race-condition"}
    assert "withdraw" in names, out
    assert "redeem_coupon" in names, out


def test_race_transaction_protected_not_reported():
    out = _run_detector(RaceConditionDetector(), "race_condition.py")
    names = {v.function for v in out if v.category == "race-condition"}
    assert "withdraw_safe" not in names, out


def test_race_non_financial_not_reported():
    out = _run_detector(RaceConditionDetector(), "race_condition.py")
    names = {v.function for v in out if v.category == "race-condition"}
    assert "list_users" not in names, out


# ---------------------------------------------------------------------------
# 2. Missing authentication
# ---------------------------------------------------------------------------

def test_missing_auth_unauthenticated_endpoint_reported():
    out = _run_detector(MissingAuthenticationDetector(), "missing_auth.py")
    names = {v.function for v in out if v.category == "missing-authentication"}
    assert "create_task" in names, out
    assert "get_task" in names, out


def test_missing_auth_depends_not_reported():
    out = _run_detector(MissingAuthenticationDetector(), "missing_auth.py")
    names = {v.function for v in out if v.category == "missing-authentication"}
    assert "get_task_protected" not in names, out


def test_missing_auth_health_not_reported():
    out = _run_detector(MissingAuthenticationDetector(), "missing_auth.py")
    names = {v.function for v in out if v.category == "missing-authentication"}
    assert "health" not in names, out


# ---------------------------------------------------------------------------
# 3. SQL ``?`` parameterised query false positive
# ---------------------------------------------------------------------------

def test_sql_question_mark_parameterised_not_reported():
    out = _run_detector(SQLInjectionDetector(), "sql_param.py")
    names = {v.function for v in out if v.category == "sql-injection"}
    assert "safe_coupon_redeem" not in names, out
    assert "safe_transfer" not in names, out


def test_sql_dynamic_still_reported():
    out = _run_detector(SQLInjectionDetector(), "sql_param.py")
    names = {v.function for v in out if v.category == "sql-injection"}
    assert "vulnerable" in names, out


# ---------------------------------------------------------------------------
# 4. SSRF constant-URL false positive
# ---------------------------------------------------------------------------

def test_ssrf_config_constant_not_reported():
    out = _run_detector(SSRFDetector(), "ssrf_const.py")
    names = {v.function for v in out if v.category == "ssrf"}
    # ``sync_products`` reads PRODUCT_SERVICE_URL from env config, not request.
    assert "sync_products" not in names, out


def test_ssrf_request_url_still_reported():
    out = _run_detector(SSRFDetector(), "ssrf_const.py")
    names = {v.function for v in out if v.category == "ssrf"}
    assert "proxy_request" in names, out


# ---------------------------------------------------------------------------
# 5. taint_names termination (the vulnbank hang regression)
# ---------------------------------------------------------------------------

def test_taint_names_terminates_on_self_assign_oscillation():
    """Reproduce the upload_profile_picture pattern that hung at 100 % CPU.

    ``filename = secure_filename(...)`` then ``filename = f"...{filename}"``
    previously flipped in/out of the tainted set forever.  Whole-word matching
    + a pass cap must make it return promptly.
    """
    src = (
        "def upload_profile_picture(current_user):\n"
        "    file = request.files['profile_picture']\n"
        "    filename = secure_filename(file.filename)\n"
        "    filename = f\"{random.randint(1, 1000000)}_{filename}\"\n"
        "    file_path = os.path.join(UPLOAD_FOLDER, filename)\n"
        "    file.save(file_path)\n"
    )
    path = Path("/tmp/_v060_taint.py")
    path.write_text(src, encoding="utf-8")
    ir = extract_python(path)
    fn = ir.functions[0]
    # Must return (not hang).
    result = taint_names(fn)
    assert isinstance(result, set)
