"""Tests for vulnresearch.cli (backward compatibility + new options)."""
from __future__ import annotations

import json

from vulnresearch.cli import main


VULN_SRC = (
    "def view(user_id):\n"
    "    query = f\"SELECT * FROM users WHERE id={user_id}\"\n"
    "    db.execute(query)\n"
)


def _make_app(tmp_path):
    (tmp_path / "app.py").write_text(VULN_SRC, encoding="utf-8")
    return tmp_path


def test_text_default_output(tmp_path, capsys):
    _make_app(tmp_path)
    rc = main([str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 0
    assert "Scanned:" in captured.err
    assert "Findings:" in captured.err
    assert "SQL Injection" in captured.out


def test_json_flag_backward_compat(tmp_path, capsys):
    _make_app(tmp_path)
    out_file = tmp_path / "out.json"
    rc = main([str(tmp_path), "--json", str(out_file)])
    assert rc == 0
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) >= 1


def test_sarif_flag_backward_compat(tmp_path, capsys):
    _make_app(tmp_path)
    out_file = tmp_path / "out.sarif"
    rc = main([str(tmp_path), "--sarif", str(out_file)])
    assert rc == 0
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"


def test_report_flag_writes_markdown(tmp_path, capsys):
    _make_app(tmp_path)
    report_file = tmp_path / "report.md"
    rc = main([str(tmp_path), "--report", str(report_file)])
    assert rc == 0
    assert report_file.exists()
    md = report_file.read_text(encoding="utf-8")
    assert "Security Report" in md
    assert "## 1. Summary" in md
    assert "## 15. Regression Test" in md


def test_ir_flag_output(tmp_path, capsys):
    _make_app(tmp_path)
    ir_file = tmp_path / "ir.json"
    rc = main([str(tmp_path), "--ir", str(ir_file)])
    assert rc == 0
    data = json.loads(ir_file.read_text(encoding="utf-8"))
    assert "functions" in data


def test_attack_surface_flag(tmp_path, capsys):
    _make_app(tmp_path)
    rc = main([str(tmp_path), "--attack-surface"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Attack surface" in out


def test_format_report_outputs_markdown(tmp_path, capsys):
    _make_app(tmp_path)
    rc = main([str(tmp_path), "--format", "report"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "## 1. Summary" in out


def test_max_files_option_parsed(tmp_path, capsys):
    _make_app(tmp_path)
    rc = main([str(tmp_path), "--max-files", "1"])
    assert rc == 0


def test_verbose_flag(tmp_path, capsys):
    _make_app(tmp_path)
    rc = main([str(tmp_path), "--verbose"])
    out = capsys.readouterr().out
    assert rc == 0
