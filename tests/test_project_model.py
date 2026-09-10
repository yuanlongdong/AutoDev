"""Tests for vulnresearch.project_model."""
from __future__ import annotations

from pathlib import Path

from vulnresearch.project_model import ProjectModeler, trust_boundary_summary


def _make_flask_project(root: Path) -> None:
    (root / "requirements.txt").write_text("flask==2.0\n", encoding="utf-8")
    (root / "app.py").write_text(
        "from flask import Flask, request\n"
        "import psycopg2\n"
        "import redis\n"
        "\n"
        "app = Flask(__name__)\n"
        "\n"
        "@app.route('/user')\n"
        "def get_user():\n"
        "    uid = request.args.get('id')\n"
        "    cur.execute('SELECT * FROM users WHERE id=' + uid)\n"
        "    return open('/data/' + uid).read()\n",
        encoding="utf-8",
    )


def test_language_detection(tmp_path: Path):
    _make_flask_project(tmp_path)
    model = ProjectModeler().build(str(tmp_path))
    assert model.language == "python"


def test_framework_detection(tmp_path: Path):
    _make_flask_project(tmp_path)
    model = ProjectModeler().build(str(tmp_path))
    assert "flask" in model.frameworks


def test_build_system_and_package_manager(tmp_path: Path):
    _make_flask_project(tmp_path)
    model = ProjectModeler().build(str(tmp_path))
    assert model.package_manager == "pip"
    assert model.build_system in ("pip", "setuptools/poetry")


def test_database_detection(tmp_path: Path):
    _make_flask_project(tmp_path)
    model = ProjectModeler().build(str(tmp_path))
    assert "postgresql" in model.databases
    assert "redis" in model.databases or "redis" in model.caches


def test_trust_boundary_identification(tmp_path: Path):
    _make_flask_project(tmp_path)
    model = ProjectModeler().build(str(tmp_path))
    types = {b["type"] for b in model.trust_boundaries}
    assert "Network Boundary" in types       # @app.route + outbound
    assert "Database Boundary" in types      # execute()
    assert "Filesystem Boundary" in types   # open()


def test_summary_is_non_empty(tmp_path: Path):
    _make_flask_project(tmp_path)
    model = ProjectModeler().build(str(tmp_path))
    summary = trust_boundary_summary(model)
    assert "Language: python" in summary
    assert "Trust boundaries identified:" in summary
