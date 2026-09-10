"""Tests for v0.2.2 XSS source tracking and SSRF location dedup.

XSS is now gated by intra-procedural taint tracking: only f-strings that
interpolate a value flowing from a tainted source (``request.*`` / ``session.*``
/ a route-handler parameter) are reported; database rows, hash / encoding
results and subprocess output are treated as safe.  SSRF findings reported on
the same line by both the legacy regex scanner and the structured IR detector
collapse into one.
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.detectors import XSSDetector
from vulnresearch.engine import ResearchEngine

FIXTURES = Path(__file__).parent / "fixtures" / "xss_source_tracking"


def _detect_xss(source: str):
    """Run the XSSDetector over in-memory source and return XSS findings."""
    p = Path("/tmp/_xss_taint_test.py")
    p.write_text(source, encoding="utf-8")
    ir = extract_python(p)
    lines = source.splitlines()
    detector = XSSDetector()
    out = []
    for fn in ir.functions:
        out.extend(detector.detect(fn, lines, ir))
    return [v for v in out if v.category == "xss"]


# ---------------------------------------------------------------------------
# True positives — must be reported
# ---------------------------------------------------------------------------

def test_xss_request_input_detected():
    src = (
        "def handler():\n"
        "    name = request.args.get('name')\n"
        "    return f\"<h1>{name}</h1>\"\n"
    )
    assert _detect_xss(src), "request.args input must be flagged as XSS"


def test_xss_handler_param_detected():
    src = (
        "@app.route('/user/<name>')\n"
        "def view(name):\n"
        "    return f\"<h1>{name}</h1>\"\n"
    )
    assert _detect_xss(src), "route-handler parameter must be flagged as XSS"


def test_xss_session_input_detected():
    src = (
        "def handler():\n"
        "    q = session.get('q')\n"
        "    return f\"<li>{q}</li>\"\n"
    )
    assert _detect_xss(src), "session input must be flagged as XSS"


def test_xss_taint_propagation():
    # a = request input; b = a; interpolate b → must still be tainted
    src = (
        "def handler():\n"
        "    a = request.args.get('x')\n"
        "    b = a\n"
        "    return f\"<p>{b}</p>\"\n"
    )
    assert _detect_xss(src), "taint must propagate through simple assignments"


# ---------------------------------------------------------------------------
# False positives — must NOT be reported
# ---------------------------------------------------------------------------

def test_xss_db_output_not_reported():
    src = (
        "def handler():\n"
        "    user = db.execute('SELECT 1').fetchone()\n"
        "    return f\"<p>{user.username}</p>\"\n"
    )
    assert not _detect_xss(src), "database row output must not be flagged as XSS"


def test_xss_hash_output_not_reported():
    src = (
        "def handler(x):\n"
        "    h = hashlib.md5(x.encode()).hexdigest()\n"
        "    return f\"<p>Hash: {h}</p>\"\n"
    )
    assert not _detect_xss(src), "hash digest output must not be flagged as XSS"


def test_xss_command_output_not_reported():
    src = (
        "def handler(cmd):\n"
        "    result = subprocess.check_output(cmd)\n"
        "    return f\"<pre>{result.decode()}</pre>\"\n"
    )
    assert not _detect_xss(src), "subprocess output must not be flagged as XSS"


def test_xss_static_template_not_reported():
    src = (
        "def handler():\n"
        "    name = request.args.get('name')\n"
        "    return render_template_string(\"Hello {{ name }}\", name=name)\n"
    )
    results = _detect_xss(src)
    assert not results, "static template + context var must not be flagged as XSS/SSTI"


# ---------------------------------------------------------------------------
# Fixture-driven checks
# ---------------------------------------------------------------------------

def test_xss_true_positives_fixture():
    p = FIXTURES / "xss_true_positives.py"
    ir = extract_python(p)
    lines = p.read_text().splitlines()
    detector = XSSDetector()
    results = []
    for fn in ir.functions:
        results.extend(detector.detect(fn, lines, ir))
    assert len([v for v in results if v.category == "xss"]) == 3, \
        f"expected 3 true-positive XSS, got {len(results)}: {[v.line for v in results]}"


def test_xss_false_positives_fixture():
    p = FIXTURES / "xss_false_positives.py"
    ir = extract_python(p)
    lines = p.read_text().splitlines()
    detector = XSSDetector()
    results = []
    for fn in ir.functions:
        results.extend(detector.detect(fn, lines, ir))
    assert not [v for v in results if v.category == "xss"], \
        f"false positives leaked: {[(v.line, v.snippet) for v in results]}"


# ---------------------------------------------------------------------------
# SSRF location dedup
# ---------------------------------------------------------------------------

def test_ssrf_deduplication_same_line(tmp_path: Path):
    """Legacy regex + structured detector on the SAME SSRF line → one finding."""
    (tmp_path / "app.py").write_text(
        "import requests\n"
        "from flask import request\n"
        "def fetch():\n"
        "    url = request.args.get('url', '')\n"
        "    resp = requests.get(url)\n"
        "    return resp.text\n",
        encoding="utf-8",
    )
    findings = ResearchEngine(str(tmp_path)).run()
    ssrf = [f for f in findings if f.category == "ssrf"]
    assert len(ssrf) == 1, f"expected 1 deduped SSRF, got {len(ssrf)}: {[(f.line, f.snippet) for f in ssrf]}"


def test_ssrf_different_categories_not_merged(tmp_path: Path):
    """path-traversal and arbitrary-file-write on the SAME line must NOT merge."""
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def save():\n"
        "    name = request.args.get('f')\n"
        "    open(name, 'w').write('x')\n"
    )
    findings = ResearchEngine(str(tmp_path)).run()
    cats = {f.category for f in findings}
    assert "path-traversal" in cats, f"path-traversal missing: {cats}"
    assert "arbitrary-file-write" in cats, f"arbitrary-file-write missing: {cats}"
    # the two categories must survive as distinct findings (not collapsed)
    pt = [f for f in findings if f.category == "path-traversal"]
    afw = [f for f in findings if f.category == "arbitrary-file-write"]
    assert len(pt) >= 1 and len(afw) >= 1
    assert len(pt) + len(afw) >= 2, "different categories on the same line were wrongly merged"
