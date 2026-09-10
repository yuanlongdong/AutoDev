"""Tests for vulnresearch.asset_analyzer."""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.project_model import ProjectModeler
from vulnresearch.asset_analyzer import AssetAnalyzer, CodeAsset


def _write_app(root: Path) -> Path:
    p = root / "app.py"
    p.write_text(
        "from flask import Flask, request\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/user')\n"
        "def get_user():\n"
        "    return {'id': request.args.get('id')}\n"
        "\n"
        "@app.route('/admin/users')\n"
        "def admin_users():\n"
        "    return 'all users'\n"
        "\n"
        "@app.route('/api/internal/debug')\n"
        "def internal_debug():\n"
        "    return 'debug'\n"
        "\n"
        "def consume_message(payload):\n"
        "    print(payload)\n"
        "\n"
        "def parse_config(filename):\n"
        "    return open(filename).read()\n",
        encoding="utf-8",
    )
    return p


def test_http_handler_recognized(tmp_path: Path):
    p = _write_app(tmp_path)
    ir = extract_python(p)
    model = ProjectModeler().build(str(tmp_path))
    surface = AssetAnalyzer().analyze(ir, model)
    handler_types = [a.type for a in surface.assets]
    assert "http_handler" in handler_types


def test_admin_api_recognized(tmp_path: Path):
    p = _write_app(tmp_path)
    ir = extract_python(p)
    model = ProjectModeler().build(str(tmp_path))
    surface = AssetAnalyzer().analyze(ir, model)
    admin = [a for a in surface.assets if a.type == "admin_api"]
    assert admin, "admin_api asset should be detected"
    assert admin[0].name == "admin_users"


def test_internal_api_recognized(tmp_path: Path):
    p = _write_app(tmp_path)
    ir = extract_python(p)
    model = ProjectModeler().build(str(tmp_path))
    surface = AssetAnalyzer().analyze(ir, model)
    internal = [a for a in surface.assets if a.type == "internal_api"]
    assert internal, "internal_api asset should be detected"
    assert internal[0].name == "internal_debug"


def test_attack_surface_entry_points_populated(tmp_path: Path):
    p = _write_app(tmp_path)
    ir = extract_python(p)
    model = ProjectModeler().build(str(tmp_path))
    surface = AssetAnalyzer().analyze(ir, model)
    assert len(surface.entry_points) >= 3
    names = [ep for ep in surface.entry_points]
    assert any("admin_users" in n for n in names)
    assert any("internal_debug" in n for n in names)


def test_queue_consumer_recognized(tmp_path: Path):
    p = _write_app(tmp_path)
    ir = extract_python(p)
    model = ProjectModeler().build(str(tmp_path))
    surface = AssetAnalyzer().analyze(ir, model)
    types = [a.type for a in surface.assets]
    assert "queue_consumer" in types


def test_file_parser_recognized(tmp_path: Path):
    p = _write_app(tmp_path)
    ir = extract_python(p)
    model = ProjectModeler().build(str(tmp_path))
    surface = AssetAnalyzer().analyze(ir, model)
    types = [a.type for a in surface.assets]
    assert "file_parser" in types
