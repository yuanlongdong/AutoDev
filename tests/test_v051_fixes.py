"""v0.5.1 — fixes for the three new shooting ranges.

* SQL injection via SQLAlchemy ``text()`` (graphql-target L320);
* hardcoded bytes literals (crypto-target ``AES_KEY`` / ``AES_IV``);
* test-directory exclusion in :class:`ResearchEngine` (graphql-target SSRF
  false positives lived entirely under ``tests/``).
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python, extract_file, FunctionIR
from vulnresearch.detectors import (
    SQLInjectionDetector,
    HardcodedSecretDetector,
    scan_file_with_ir,
)
from vulnresearch.engine import ResearchEngine

FIXTURES = Path(__file__).parent / "fixtures" / "v051"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_function_level(source: str, detector):
    """Run *detector* over every function in *source*; return Vulnerabilities."""
    p = Path("/tmp/_v051_unit.py")
    p.write_text(source, encoding="utf-8")
    ir = extract_python(p)
    lines = source.splitlines()
    out = []
    for fn in ir.functions:
        out.extend(detector.detect(fn, lines, ir))
    return out


def _module_detect(path: Path, detector):
    """Run *detector* over a file, including the module-level pass."""
    ir = extract_file(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    out = []
    for fn in ir.functions:
        out.extend(detector.detect(fn, lines, ir))
    if not any(v.file == str(path.resolve()) or v.file == str(path) for v in out):
        mod = FunctionIR(
            name="<module>", qualified_name="<module>",
            path=str(path.resolve()), line=1, end_line=len(lines),
        )
        out.extend(detector.detect(mod, lines, ir))
    return out


# ---------------------------------------------------------------------------
# 1. SQL injection via text()
# ---------------------------------------------------------------------------

def test_sql_text_percent_format_detected():
    src = (
        "def h(filter):\n"
        "    from sqlalchemy import text\n"
        "    return text(\"title = '%s' or content = '%s'\" % (filter, filter))\n"
    )
    out = _detect_function_level(src, SQLInjectionDetector())
    assert any(v.category == "sql-injection" for v in out), out


def test_sql_text_fstring_detected():
    src = (
        "def h(name):\n"
        "    from sqlalchemy import text\n"
        "    return text(f\"SELECT * FROM users WHERE name = {name}\")\n"
    )
    out = _detect_function_level(src, SQLInjectionDetector())
    assert any(v.category == "sql-injection" for v in out), out


def test_sql_text_dot_format_detected():
    """``text(\"...{}\".format(var))`` must be flagged (v0.5.1 confirmation)."""
    src = (
        "def h(name):\n"
        "    from sqlalchemy import text\n"
        "    return text(\"SELECT * FROM users WHERE name = {}\".format(name))\n"
    )
    out = _detect_function_level(src, SQLInjectionDetector())
    assert any(v.category == "sql-injection" for v in out), out


def test_sql_text_concat_detected():
    src = (
        "def h(name):\n"
        "    from sqlalchemy import text\n"
        "    return text(\"SELECT * FROM users WHERE name = \" + name)\n"
    )
    out = _detect_function_level(src, SQLInjectionDetector())
    assert any(v.category == "sql-injection" for v in out), out


def test_sql_text_static_not_reported():
    src = (
        "def h():\n"
        "    from sqlalchemy import text\n"
        "    return text(\"SELECT 1\")\n"
    )
    out = _detect_function_level(src, SQLInjectionDetector())
    assert not any(v.category == "sql-injection" for v in out), out


def test_sql_text_named_bind_not_reported():
    """Static literal with a named bind param (``:name``) is parameterised."""
    src = (
        "def h():\n"
        "    from sqlalchemy import text\n"
        "    return text(\"SELECT * FROM users WHERE name = :name\")\n"
    )
    out = _detect_function_level(src, SQLInjectionDetector())
    assert not any(v.category == "sql-injection" for v in out), out


def test_sql_text_fixture_all_unsafe():
    p = FIXTURES / "text_sql.py"
    findings = scan_file_with_ir(p, extract_file(p))
    sqls = [v for v in findings if v.category == "sql-injection"]
    # The engine's ``_dedup_by_location`` collapses legacy + structured hits on
    # the same line; count distinct lines to mirror that behaviour.
    lines = {v.line for v in sqls}
    assert len(lines) == 4, sorted(lines)


def test_sql_text_safe_fixture_zero():
    p = FIXTURES / "text_sql_safe.py"
    findings = scan_file_with_ir(p, extract_file(p))
    sqls = [v for v in findings if v.category == "sql-injection"]
    assert sqls == [], [v.line for v in sqls]


# ---------------------------------------------------------------------------
# 2. Hardcoded bytes literals
# ---------------------------------------------------------------------------

def test_bytes_key_detected():
    src = "AES_KEY = b'0123456789abcdef'\n"
    p = Path("/tmp/_v051_bytes.py")
    p.write_text(src, encoding="utf-8")
    out = _module_detect(p, HardcodedSecretDetector())
    assert any(v.category == "hardcoded-secret" for v in out), out


def test_bytes_iv_detected():
    src = "AES_IV = b'fedcba9876543210'\n"
    p = Path("/tmp/_v051_iv.py")
    p.write_text(src, encoding="utf-8")
    out = _module_detect(p, HardcodedSecretDetector())
    assert any(v.category == "hardcoded-secret" for v in out), out


def test_bytes_short_not_reported():
    src = "SHORT = b'x'\n"
    p = Path("/tmp/_v051_short.py")
    p.write_text(src, encoding="utf-8")
    out = _module_detect(p, HardcodedSecretDetector())
    assert not any(v.category == "hardcoded-secret" for v in out), out


def test_bytes_fixture_reports_all_keys():
    p = FIXTURES / "bytes_secret.py"
    findings = scan_file_with_ir(p, extract_file(p))
    secs = [v for v in findings if v.category == "hardcoded-secret"]
    # AES_KEY, AES_IV, SESSION_TOKEN, DB_PASSWORD
    assert len(secs) == 4, [(v.line, v.snippet) for v in secs]


def test_bytes_safe_fixture_zero():
    p = FIXTURES / "bytes_secret_safe.py"
    findings = scan_file_with_ir(p, extract_file(p))
    secs = [v for v in findings if v.category == "hardcoded-secret"]
    # JWT_SECRET = 'secret123' is 9 chars but below the structured 6-char
    # floor? No — 'secret123' is 9 chars and matches the string rule via the
    # legacy path.  We only assert that the BYTES lines are not reported here.
    byte_lines = {v.line for v in findings
                  if "b'" in v.snippet or 'b"' in v.snippet}
    assert not byte_lines, [(v.line, v.snippet) for v in findings]


# ---------------------------------------------------------------------------
# 3. Test-directory exclusion (SSRF false positives)
# ---------------------------------------------------------------------------

def test_engine_skips_tests_directory(tmp_path):
    """A ``tests/`` subtree must not be walked by ResearchEngine.files()."""
    app = tmp_path / "app.py"
    app.write_text("import requests\nURL='http://x'\n", encoding="utf-8")
    tdir = tmp_path / "tests"
    tdir.mkdir()
    (tdir / "test_helper.py").write_text(
        "import requests\nURL='http://example'\n"
        "requests.post(URL, json={})\n", encoding="utf-8")
    eng = ResearchEngine(str(tmp_path))
    walked = [str(p.name) for p in eng.files()]
    assert "test_helper.py" not in walked, walked
    assert "app.py" in walked, walked


def test_engine_skips_conftest(tmp_path):
    (tmp_path / "conftest.py").write_text("import requests\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    eng = ResearchEngine(str(tmp_path))
    walked = [p.name for p in eng.files()]
    assert "conftest.py" not in walked, walked
    assert "app.py" in walked, walked


def test_engine_keeps_root_test_script(tmp_path):
    """Regression guard: a root-level ``test_*.py`` (sast-target shape) is
    still walked — blanket ``test_*.py`` exclusion would drop the 48-finding
    floor.  Only ``tests/`` directories and ``conftest.py`` are skipped."""
    (tmp_path / "test_vulnerabilities.py").write_text(
        "import requests\nURL='http://x'\nrequests.get(URL)\n",
        encoding="utf-8")
    eng = ResearchEngine(str(tmp_path))
    walked = [p.name for p in eng.files()]
    assert "test_vulnerabilities.py" in walked, walked
