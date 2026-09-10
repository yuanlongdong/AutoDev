"""Tests for vulnresearch.auth_analyzer."""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.project_model import ProjectModeler
from vulnresearch.asset_analyzer import AssetAnalyzer
from vulnresearch.auth_analyzer import AuthAnalyzer


def _build_ir_model(root: Path, source: str):
    p = root / "app.py"
    p.write_text(source, encoding="utf-8")
    ir = extract_python(p)
    model = ProjectModeler().build(str(root))
    surface = AssetAnalyzer().analyze(ir, model)
    return ir, surface


def test_only_auth_no_authz_detected(tmp_path: Path):
    """login_required present but no permission/role check."""
    source = (
        "from functools import wraps\n"
        "def login_required(f): return f\n"
        "\n"
        "def get_current_user(): return {}\n"
        "\n"
        "@login_required\n"
        "def view_profile():\n"
        "    user = get_current_user()\n"
        "    return user\n"
    )
    ir, surface = _build_ir_model(tmp_path, source)
    findings = AuthAnalyzer().analyze(ir, surface)
    types = {f.type for f in findings}
    assert "missing_authz" in types, f"findings: {findings}"


def test_idor_detected(tmp_path: Path):
    """Caller-supplied order_id used in query with no ownership check."""
    source = (
        "from flask import request\n"
        "\n"
        "@app.route('/order/<int:order_id>')\n"
        "def get_order(order_id):\n"
        "    order = db.execute('SELECT * FROM orders WHERE id=' + str(order_id)).fetchone()\n"
        "    return order\n"
    )
    ir, surface = _build_ir_model(tmp_path, source)
    findings = AuthAnalyzer().analyze(ir, surface)
    idor = [f for f in findings if f.type == "idor"]
    assert idor, f"IDOR finding expected, got: {findings}"
    assert "order_id" in idor[0].description


def test_internal_api_without_auth_detected(tmp_path: Path):
    """Internal API route with no authentication decorator."""
    source = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/api/internal/debug')\n"
        "def internal_debug():\n"
        "    return {'env': 'debug'}\n"
    )
    ir, surface = _build_ir_model(tmp_path, source)
    findings = AuthAnalyzer().analyze(ir, surface)
    types = {f.type for f in findings}
    assert "auth_bypass" in types, f"expected auth_bypass, got: {findings}"


def test_admin_api_without_role_check(tmp_path: Path):
    source = (
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/admin/users')\n"
        "def admin_users():\n"
        "    return db.execute('SELECT * FROM users').fetchall()\n"
    )
    ir, surface = _build_ir_model(tmp_path, source)
    findings = AuthAnalyzer().analyze(ir, surface)
    types = {f.type for f in findings}
    assert "priv_esc" in types or "auth_bypass" in types, f"got: {findings}"


def test_chain_built(tmp_path: Path):
    source = (
        "def login_required(f): return f\n"
        "\n"
        "@login_required\n"
        "def handler():\n"
        "    u = get_current_user()\n"
        "    return u\n"
    )
    p = tmp_path / "app.py"
    p.write_text(source, encoding="utf-8")
    ir = extract_python(p)
    handler = next(fn for fn in ir.functions if fn.name == "handler")
    chain = AuthAnalyzer().build_auth_chain(handler)
    assert chain.authentication == "present"
    assert chain.action == "handler"
