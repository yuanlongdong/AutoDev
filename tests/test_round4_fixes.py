"""v0.3.1 – round-4 cross-validation fixes.

Covers the three bugs found while re-running the shooting range:

1. single-file scans returned zero findings (``rglob`` never yields the file);
2. AWS hardcoded keys (``AWS_ACCESS_KEY`` / ``AWS_SECRET_KEY`` / ``AKIA…``)
   were missed by the secret regex / structured detector;
3. ``eval()`` / ``exec()`` on request input was not flagged as code injection.
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.engine import ResearchEngine
from vulnresearch.ast_engine import ASTResearchEngine
from vulnresearch.ir import extract_python
from vulnresearch.detectors import CodeInjectionDetector

FIXTURES = Path(__file__).parent / "fixtures" / "round4"


def _detect(fixture: str, detector_cls=CodeInjectionDetector):
    """Run *detector_cls* over every function in the fixture file."""
    p = FIXTURES / fixture
    ir = extract_python(p)
    lines = p.read_text(encoding="utf-8").splitlines()
    out = []
    for fn in ir.functions:
        out.extend(detector_cls().detect(fn, lines, ir))
    return out


# ---------------------------------------------------------------------------
# Bug 1 – single-file scans
# ---------------------------------------------------------------------------


def test_single_file_scan_returns_findings():
    p = FIXTURES / "single_file_vuln.py"
    findings = ResearchEngine(str(p)).run()
    assert findings, "scanning a single .py file must produce findings"
    categories = {f.category for f in findings}
    assert "sql-injection" in categories


def test_single_file_ast_engine():
    p = FIXTURES / "single_file_vuln.py"
    ir = ASTResearchEngine(str(p)).run()
    names = {fn.name for fn in ir.functions}
    assert "users" in names


# ---------------------------------------------------------------------------
# Bug 2 – AWS hardcoded secrets
# ---------------------------------------------------------------------------


def test_aws_access_key_detected():
    p = FIXTURES / "aws_secrets.py"
    findings = ResearchEngine(str(p)).run()
    hits = [f for f in findings if f.category == "hardcoded-secret" and f.line == 3]
    assert hits, "AWS_ACCESS_KEY assignment must be reported as a hardcoded secret"


def test_aws_secret_key_detected():
    p = FIXTURES / "aws_secrets.py"
    findings = ResearchEngine(str(p)).run()
    hits = [f for f in findings if f.category == "hardcoded-secret" and f.line == 4]
    assert hits, "AWS_SECRET_KEY assignment must be reported as a hardcoded secret"


def test_aws_key_format_detected():
    p = FIXTURES / "aws_secrets.py"
    findings = ResearchEngine(str(p)).run()
    # The AKIA[0-9A-Z]{16} shape lives on the AWS_ACCESS_KEY line.
    akia = [
        f for f in findings
        if f.category == "hardcoded-secret" and "AKIA" in (f.snippet or "")
    ]
    assert akia, "the AKIA… AWS Access Key shape must be detected"


# ---------------------------------------------------------------------------
# Bug 3 – code injection
# ---------------------------------------------------------------------------


def test_eval_code_injection_detected():
    out = _detect("code_injection.py")
    ci = [v for v in out if v.category == "code-injection" and v.function == "deserialize"]
    assert ci, "eval(data) where data flows from request must be reported"
    assert all(v.severity == "Critical" for v in ci)


def test_exec_code_injection_detected():
    out = _detect("code_injection.py")
    ci = [v for v in out if v.category == "code-injection" and v.function == "run"]
    assert ci, "exec(user_input) where user_input flows from request must be reported"


def test_eval_static_string_not_reported():
    out = _detect("code_injection.py")
    # safe_eval only calls eval("1+1") — a static literal, must be skipped.
    ci_functions = {v.function for v in out if v.category == "code-injection"}
    assert "safe_eval" not in ci_functions
    # and exactly the two request-driven sinks are reported
    assert ci_functions == {"deserialize", "run"}
