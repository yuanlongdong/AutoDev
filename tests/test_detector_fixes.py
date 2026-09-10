"""Tests for v0.2.1 detector fixes (10 issues from OWASP range report)."""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.detectors import (
    scan_file,
    scan_file_with_ir,
    DetectorPipeline,
    CommandInjectionDetector,
    XSSDetector,
    SSRFDetector,
    SSTIDetector,
    XXEDetector,
    JWTFlawDetector,
    LdapInjectionDetector,
)

FIXTURES = Path(__file__).parent / "fixtures" / "detector_fixes"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect(source: str, detector_cls):
    p = Path("/tmp/_vuln_fix_test.py")
    p.write_text(source, encoding="utf-8")
    ir = extract_python(p)
    lines = source.splitlines()
    detector = detector_cls()
    results = []
    for fn in ir.functions:
        results.extend(detector.detect(fn, lines, ir))
    return results


def _fixture(name: str) -> Path:
    return FIXTURES / name


# ---------------------------------------------------------------------------
# 1. Command Injection
# ---------------------------------------------------------------------------

def test_command_injection_shell_true_detected():
    src = (
        "def handler(cmd):\n"
        "    import subprocess\n"
        "    subprocess.run(cmd, shell=True)\n"
    )
    r = _detect(src, CommandInjectionDetector)
    assert any(v.category == "command-injection" for v in r), f"got: {r}"


def test_command_injection_check_output_detected():
    src = (
        "def handler(user_input):\n"
        "    import subprocess\n"
        "    out = subprocess.check_output(user_input, shell=True)\n"
        "    return out\n"
    )
    r = _detect(src, CommandInjectionDetector)
    assert any(v.category == "command-injection" for v in r), f"got: {r}"


def test_command_injection_check_call_detected():
    src = (
        "def handler(user_input):\n"
        "    import subprocess\n"
        "    subprocess.check_call(user_input, shell=True)\n"
    )
    r = _detect(src, CommandInjectionDetector)
    assert any(v.category == "command-injection" for v in r), f"got: {r}"


def test_command_injection_regex_check_output_shell_true():
    p = _fixture("command_injection.py")
    findings = scan_file(p)
    assert any(f.category == "command-injection" for f in findings), f"got: {[f.category for f in findings]}"


# ---------------------------------------------------------------------------
# 2. Reflected XSS — f-string HTML
# ---------------------------------------------------------------------------

def test_xss_fstring_html_detected():
    src = (
        "def handler():\n"
        "    name = request.args.get('name')\n"
        "    return f\"<h1>Hello {name}!</h1>\"\n"
    )
    r = _detect(src, XSSDetector)
    assert any(v.category == "xss" for v in r), f"got: {r}"


def test_xss_join_list_detected():
    src = (
        "def handler(results):\n"
        "    items = \"\".join([f\"<li>{q}</li>\" for q in results])\n"
        "    return f\"<ul>{items}</ul>\"\n"
    )
    r = _detect(src, XSSDetector)
    assert any(v.category == "xss" for v in r), f"got: {r}"


def test_xss_fstring_fixture_detected():
    # v0.2.2: XSS is detected by the structured, taint-aware XSSDetector
    # (the legacy regex rule was removed).
    p = _fixture("xss_fstring.py")
    ir = extract_python(p)
    lines = p.read_text().splitlines()
    pipe = DetectorPipeline()
    results = []
    for fn in ir.functions:
        results.extend(pipe.run(fn, lines, ir))
    assert any(v.category == "xss" for v in results), f"got: {[v.category for v in results]}"


# ---------------------------------------------------------------------------
# 4. XXE
# ---------------------------------------------------------------------------

def test_xxe_detected():
    src = (
        "def handler():\n"
        "    import xml.etree.ElementTree as ET\n"
        "    user_input = request.data\n"
        "    root = ET.fromstring(user_input)\n"
    )
    r = _detect(src, XXEDetector)
    assert any(v.category == "xxe" for v in r), f"got: {r}"


def test_xxe_lxml_detected():
    src = (
        "def handler():\n"
        "    from lxml import etree\n"
        "    xml_data = request.data\n"
        "    tree = etree.fromstring(xml_data)\n"
    )
    r = _detect(src, XXEDetector)
    assert any(v.category == "xxe" for v in r), f"got: {r}"


def test_xxe_fixture_detected():
    p = _fixture("xxe_vuln.py")
    findings = scan_file(p)
    # The structured detector should fire on the fixture
    ir = extract_python(p)
    lines = p.read_text().splitlines()
    pipe = DetectorPipeline()
    results = []
    for fn in ir.functions:
        results.extend(pipe.run(fn, lines, ir))
    assert any(v.category == "xxe" for v in results), f"got: {[v.category for v in results]}"


# ---------------------------------------------------------------------------
# 5. Insecure JWT
# ---------------------------------------------------------------------------

def test_jwt_none_algorithm_detected():
    src = (
        "def handler():\n"
        "    import jwt\n"
        "    token = jwt.encode({'user': 1}, 'secret', algorithm='none')\n"
        "    return token\n"
    )
    r = _detect(src, JWTFlawDetector)
    assert any(v.category == "jwt-flaws" for v in r), f"got: {r}"


def test_jwt_verify_false_detected():
    src = (
        "def handler(token):\n"
        "    import jwt\n"
        "    data = jwt.decode(token, 'secret', verify=False)\n"
        "    return data\n"
    )
    r = _detect(src, JWTFlawDetector)
    assert any(v.category == "jwt-flaws" for v in r), f"got: {r}"


def test_jwt_options_verify_signature_false():
    src = (
        "def handler(token):\n"
        "    import jwt\n"
        "    data = jwt.decode(token, options={'verify_signature': False})\n"
        "    return data\n"
    )
    r = _detect(src, JWTFlawDetector)
    assert any(v.category == "jwt-flaws" for v in r), f"got: {r}"


# ---------------------------------------------------------------------------
# 6. LDAP Injection
# ---------------------------------------------------------------------------

def test_ldap_injection_detected():
    src = (
        "from ldap3 import Connection\n"
        "def handler(conn, username):\n"
        "    search_filter = f'(uid={username})'\n"
        "    conn.search('ou=users,dc=example,dc=com', search_filter)\n"
    )
    r = _detect(src, LdapInjectionDetector)
    assert any(v.category == "ldap-injection" for v in r), f"got: {r}"


# ---------------------------------------------------------------------------
# 7. SSRF — non-URL param must NOT trigger
# ---------------------------------------------------------------------------

def test_ssrf_not_triggered_on_non_url_param():
    src = (
        "def handler(user_id):\n"
        "    import requests\n"
        "    resp = requests.get(user_id)\n"
        "    return resp\n"
    )
    r = _detect(src, SSRFDetector)
    assert not any(v.category == "ssrf" for v in r), f"false positive: {r}"


def test_ssrf_still_triggered_on_url_param():
    src = (
        "def handler():\n"
        "    import requests\n"
        "    url = request.args.get('url')\n"
        "    resp = requests.get(url)\n"
        "    return resp\n"
    )
    r = _detect(src, SSRFDetector)
    assert any(v.category == "ssrf" for v in r), f"missed real SSRF: {r}"


def test_ssrf_safe_fixture():
    p = _fixture("ssrf_safe.py")
    ir = extract_python(p)
    lines = p.read_text().splitlines()
    detector = SSRFDetector()
    results = []
    for fn in ir.functions:
        results.extend(detector.detect(fn, lines, ir))
    assert not any(v.category == "ssrf" for v in results), f"false positive: {results}"


# ---------------------------------------------------------------------------
# 8. SSTI — static template must NOT trigger
# ---------------------------------------------------------------------------

def test_ssti_not_triggered_on_static_template():
    src = (
        "def handler():\n"
        "    name = request.args.get('name')\n"
        "    return render_template_string('Hello {{ name }}', name=name)\n"
    )
    r = _detect(src, SSTIDetector)
    assert not any(v.category == "ssti" for v in r), f"false positive: {r}"


def test_ssti_still_triggered_on_dynamic_template():
    src = (
        "def handler():\n"
        "    name = request.args.get('name')\n"
        "    tmpl = '<h1>' + name + '</h1>'\n"
        "    return render_template_string(tmpl)\n"
    )
    r = _detect(src, SSTIDetector)
    assert any(v.category == "ssti" for v in r), f"missed real SSTI: {r}"


def test_ssti_safe_fixture():
    p = _fixture("ssti_safe.py")
    ir = extract_python(p)
    lines = p.read_text().splitlines()
    detector = SSTIDetector()
    results = []
    for fn in ir.functions:
        results.extend(detector.detect(fn, lines, ir))
    assert not any(v.category == "ssti" for v in results), f"false positive: {results}"


# ---------------------------------------------------------------------------
# 9. Import lines skipped
# ---------------------------------------------------------------------------

def test_import_lines_skipped():
    p = _fixture("safe_imports.py")
    findings = scan_file(p)
    # Import lines should not produce XSS findings
    assert not any(f.category == "xss" for f in findings), \
        f"import lines falsely reported as XSS: {[(f.line, f.snippet) for f in findings]}"


# ---------------------------------------------------------------------------
# 10. Secret deduplication
# ---------------------------------------------------------------------------

def test_secret_deduplication():
    """legacy regex 'secret' and structured 'hardcoded-secret' on the same
    line should collapse into a single 'hardcoded-secret' finding."""
    from vulnresearch.engine import ResearchEngine

    tmp = Path("/tmp/_vuln_dedup_test")
    tmp.mkdir(exist_ok=True)
    (tmp / "app.py").write_text(
        "API_KEY = 'sk-live-abcdefghijklmnop'\n"
        "def handler():\n"
        "    return API_KEY\n",
        encoding="utf-8",
    )
    engine = ResearchEngine(str(tmp))
    findings = engine.run()
    secret_findings = [f for f in findings if f.category in ("secret", "hardcoded-secret")]
    # After normalization there must be no legacy 'secret' category
    assert not any(f.category == "secret" for f in secret_findings), \
        f"legacy 'secret' category not normalized: {[f.category for f in secret_findings]}"
    # Exactly one finding for the hardcoded secret
    assert len(secret_findings) == 1, \
        f"expected 1 deduped finding, got {len(secret_findings)}: {[(f.category, f.line) for f in secret_findings]}"
    assert secret_findings[0].category == "hardcoded-secret"
