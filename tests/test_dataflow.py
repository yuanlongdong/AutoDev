"""Tests for the intra-procedural data-flow analysis."""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.dataflow import (
    DataFlowAnalyzer,
    DataFlowResult,
    Definition,
    Use,
    is_tainted,
    is_tainted_at,
)


def _analyze(tmp_path: Path, src: str, fn_name: str = "f") -> DataFlowResult:
    p = tmp_path / "m.py"
    p.write_text(src, encoding="utf-8")
    ir = extract_python(p)
    fn = next(f for f in ir.functions if f.name == fn_name)
    return DataFlowAnalyzer().analyze(fn, src.splitlines())


def test_definitions_and_use_chains(tmp_path: Path):
    result = _analyze(tmp_path,
        "def f():\n"
        "    x = request.args.get('id')\n"
        "    y = process(x)\n"
        "    output(y)\n"
    )
    var_names = {d.var_name for d in result.definitions}
    assert "x" in var_names
    assert "y" in var_names
    x_uses = result.def_use_chains.get("x", [])
    assert any(u.context == "call:process" for u in x_uses)
    y_uses = result.def_use_chains.get("y", [])
    assert any(u.context == "call:output" for u in y_uses)


def test_definition_records_line_and_expression(tmp_path: Path):
    result = _analyze(tmp_path,
        "def f():\n"
        "    x = request.args.get('id')\n",
    )
    x_def = next(d for d in result.definitions if d.var_name == "x")
    assert x_def.line == 2
    assert "request.args.get" in x_def.expression


def test_tainted_variable_from_source(tmp_path: Path):
    result = _analyze(tmp_path,
        "def f():\n"
        "    x = request.args.get('id')\n"
        "    y = process(x)\n"
        "    output(y)\n",
    )
    assert is_tainted("x", result, []) is True
    # Taint now propagates through ordinary variable dependencies.
    assert is_tainted("y", result, []) is True


def test_transitive_taint_through_multiple_assignments(tmp_path: Path):
    result = _analyze(tmp_path,
        "def f():\n"
        "    raw = request.args.get('id')\n"
        "    first = raw\n"
        "    second = first\n"
        "    output(second)\n",
    )
    assert is_tainted("second", result, []) is True


def test_redefinition_takes_latest_definition(tmp_path: Path):
    result = _analyze(tmp_path,
        "def f():\n"
        "    x = request.args.get('id')\n"
        "    x = \"safe\"\n"
        "    output(x)\n",
    )
    assert is_tainted("x", result, []) is False
    x_defs = [d for d in result.definitions if d.var_name == "x"]
    assert len(x_defs) == 2
    assert max(d.line for d in x_defs) == 3


def test_taint_at_point_respects_redefinition(tmp_path: Path):
    result = _analyze(tmp_path,
        "def f():\n"
        "    x = request.args.get('id')\n"
        "    before = x\n"
        "    x = \"safe\"\n"
        "    after = x\n"
    )
    assert is_tainted_at("x", result, 3) is True
    assert is_tainted_at("before", result, 3) is True
    assert is_tainted_at("x", result, 5) is False
    assert is_tainted_at("after", result, 5) is False


def test_source_text_inside_string_is_not_source(tmp_path: Path):
    result = _analyze(tmp_path,
        "def f():\n"
        "    x = \"request.args.get\"\n"
        "    output(x)\n",
    )
    assert is_tainted("x", result, []) is False


def test_use_in_return_value(tmp_path: Path):
    result = _analyze(tmp_path,
        "def f():\n"
        "    x = 1\n"
        "    return x\n",
    )
    uses = [u for u in result.uses if u.var_name == "x"]
    assert any(u.context == "return" for u in uses)
