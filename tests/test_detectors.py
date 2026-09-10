"""Tests for vulnresearch.detectors (structured detectors + legacy compat)."""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.detectors import (
    RULES,
    scan_file,
    scan_file_with_ir,
    DetectorPipeline,
    SQLInjectionDetector,
    CommandInjectionDetector,
    PathTraversalDetector,
    SSRFDetector,
    XSSDetector,
    SSTIDetector,
    HardcodedSecretDetector,
    DangerousDeserializationDetector,
    ArbitraryFileWriteDetector,
    FileUploadDetector,
    OpenRedirectDetector,
    WeakCryptoDetector,
    InsecureDefaultDetector,
    AuthBypassDetector,
    IDORDetector,
    NoSQLInjectionDetector,
)


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


def test_legacy_rules_list_unchanged():
    # v0.2.2: the legacy XSS regex was removed; XSS/SSTI are now handled by
    # the structured taint-aware detectors.
    # v0.3.1: a 7th legacy rule was added for the AWS Access Key ID shape
    # (AKIA[0-9A-Z]{16}) so module-level AWS keys are still caught even when a
    # file defines no function (and thus no structured detector runs).
    assert len(RULES) == 7
    categories = {r[1] for r in RULES}
    assert "sql-injection" in categories
    assert "command-injection" in categories
    # XSS is no longer a legacy regex rule — it lives in the structured layer.
    assert "xss" not in categories


def test_legacy_scan_file_still_works(tmp_path: Path):
    p = tmp_path / "app.py"
    p.write_text("db.execute(f'SELECT * FROM users WHERE id={x}')\n", encoding="utf-8")
    findings = scan_file(p)
    assert findings, "legacy scan_file should still produce findings"
    assert findings[0].category == "sql-injection"


# ---------------------------------------------------------------------------
# Structured detector smoke tests
# ---------------------------------------------------------------------------


def _detect(source: str, detector_cls):
    p = Path("/tmp/_vuln_test.py")
    p.write_text(source, encoding="utf-8")
    ir = extract_python(p)
    lines = source.splitlines()
    detector = detector_cls()
    results = []
    for fn in ir.functions:
        results.extend(detector.detect(fn, lines, ir))
    return results


def test_sql_injection_detected():
    src = (
        "def handler(user_id):\n"
        "    query = f'SELECT * FROM users WHERE id={user_id}'\n"
        "    db.execute(query)\n"
    )
    r = _detect(src, SQLInjectionDetector)
    assert any(v.category == "sql-injection" for v in r), f"got: {r}"


def test_sql_injection_orm_safe_not_flagged():
    """Parameterised ORM-style query must NOT be reported."""
    src = (
        "def handler(user_id):\n"
        "    db.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
    )
    r = _detect(src, SQLInjectionDetector)
    assert not any(v.category == "sql-injection" for v in r), f"false positive: {r}"


def test_command_injection_detected():
    src = (
        "def handler(host):\n"
        "    import os\n"
        "    os.system(f'ping -c 1 {host}')\n"
    )
    r = _detect(src, CommandInjectionDetector)
    assert any(v.category == "command-injection" for v in r)


def test_path_traversal_detected():
    src = (
        "def handler():\n"
        "    path = request.args.get('path')\n"
        "    return open(path).read()\n"
    )
    r = _detect(src, PathTraversalDetector)
    assert any(v.category == "path-traversal" for v in r)


def test_ssrf_detected():
    src = (
        "def handler():\n"
        "    url = request.args.get('url')\n"
        "    import requests\n"
        "    return requests.get(url).text\n"
    )
    r = _detect(src, SSRFDetector)
    assert any(v.category == "ssrf" for v in r)


def test_xss_detected():
    src = (
        "def handler():\n"
        "    from markupsafe import Markup\n"
        "    name = request.args.get('name')\n"
        "    return Markup('<b>' + name + '</b>')\n"
    )
    r = _detect(src, XSSDetector)
    assert any(v.category == "xss" for v in r)


def test_ssti_detected():
    src = (
        "def handler():\n"
        "    name = request.args.get('name')\n"
        "    tmpl = '<h1>' + name + '</h1>'\n"
        "    return render_template_string(tmpl)\n"
    )
    r = _detect(src, SSTIDetector)
    assert any(v.category == "ssti" for v in r)


def test_hardcoded_secret_detected():
    src = (
        "API_KEY = 'sk-live-abcdefghijklmnop'\n"
        "def handler():\n"
        "    return API_KEY\n"
    )
    r = _detect(src, HardcodedSecretDetector)
    assert any(v.category == "hardcoded-secret" for v in r)


def test_dangerous_deserialization_detected():
    src = (
        "def handler():\n"
        "    import pickle\n"
        "    data = request.data\n"
        "    return pickle.loads(data)\n"
    )
    r = _detect(src, DangerousDeserializationDetector)
    assert any(v.category == "insecure-deserialization" for v in r)


def test_arbitrary_file_write_detected():
    src = (
        "def handler():\n"
        "    path = request.args.get('path')\n"
        "    content = request.args.get('content')\n"
        "    with open(path, 'w') as f:\n"
        "        f.write(content)\n"
    )
    r = _detect(src, ArbitraryFileWriteDetector)
    assert any(v.category == "arbitrary-file-write" for v in r)


def test_file_upload_detected():
    src = (
        "def upload():\n"
        "    f = request.files['file']\n"
        "    f.save('/uploads/' + f.filename)\n"
    )
    r = _detect(src, FileUploadDetector)
    assert any(v.category == "file-upload" for v in r)


def test_open_redirect_detected():
    src = (
        "def handler():\n"
        "    target = request.args.get('next')\n"
        "    return redirect(target)\n"
    )
    r = _detect(src, OpenRedirectDetector)
    assert any(v.category == "open-redirect" for v in r)


def test_weak_crypto_detected():
    src = (
        "def handler():\n"
        "    import hashlib\n"
        "    return hashlib.md5(b'abc').hexdigest()\n"
    )
    r = _detect(src, WeakCryptoDetector)
    assert any(v.category == "weak-cryptography" for v in r)


def test_insecure_defaults_detected():
    src = (
        "def handler():\n"
        "    app.run(host='0.0.0.0', debug=True)\n"
    )
    r = _detect(src, InsecureDefaultDetector)
    assert any(v.category == "insecure-defaults" for v in r)


def test_auth_bypass_admin_route_detected():
    src = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/admin/users')\n"
        "def admin_users():\n"
        "    return 'users'\n"
    )
    r = _detect(src, AuthBypassDetector)
    assert any(v.category == "auth-bypass" for v in r)


def test_idor_detector():
    # v0.3.0: IDOR now requires a real route handler (decorated) whose id
    # parameter reaches a DB lookup without an authorization check.
    src = (
        "@app.route('/orders/<int:order_id>')\n"
        "def get_order(order_id):\n"
        "    order = db.execute('SELECT * FROM orders WHERE id=' + str(order_id)).fetchone()\n"
        "    return order\n"
    )
    r = _detect(src, IDORDetector)
    assert any(v.category == "idor" for v in r)


def test_nosql_injection_detector():
    src = (
        "def handler():\n"
        "    uid = request.args.get('id')\n"
        "    doc = db.users.find_one({'_id': uid})\n"
        "    return doc\n"
    )
    r = _detect(src, NoSQLInjectionDetector)
    assert any(v.category == "nosql-injection" for v in r)


# ---------------------------------------------------------------------------
# Pipeline + combined entry point
# ---------------------------------------------------------------------------


def test_pipeline_runs_all_detectors(tmp_path: Path):
    p = tmp_path / "app.py"
    p.write_text(
        "import os, pickle, hashlib, requests\n"
        "from flask import Flask, request, redirect, render_template_string\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/user')\n"
        "def get_user():\n"
        "    uid = request.args.get('id')\n"
        "    db.execute(f'SELECT * FROM users WHERE id={uid}')\n"
        "    os.system('ping ' + uid)\n"
        "    url = request.args.get('url')\n"
        "    requests.get(url)\n"
        "    return redirect(url)\n",
        encoding="utf-8",
    )
    ir = extract_python(p)
    lines = p.read_text(encoding="utf-8").splitlines()
    pipeline = DetectorPipeline()
    fn = ir.functions[0]
    results = pipeline.run(fn, lines, ir)
    cats = {v.category for v in results}
    # expect several categories to fire on this vulnerable function
    assert "sql-injection" in cats
    assert "command-injection" in cats
    assert "ssrf" in cats
    assert "open-redirect" in cats


def test_scan_file_with_ir_returns_vulns(tmp_path: Path):
    p = tmp_path / "app.py"
    p.write_text(
        "API_KEY = 'sk-live-abcdefghijklmnop'\n"
        "def handler():\n"
        "    uid = request.args.get('id')\n"
        "    db.execute(f'SELECT * FROM users WHERE id={uid}')\n",
        encoding="utf-8",
    )
    ir = extract_python(p)
    vulns = scan_file_with_ir(p, ir)
    assert len(vulns) >= 1
    # all results are Vulnerability objects with required fields
    for v in vulns:
        assert v.id
        assert v.title
        assert v.category
        assert v.severity
        assert v.file
        assert v.evidence.level == "E1"
