"""Tests for the PHASE 2 AST extensions in :mod:`vulnresearch.ir`."""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import (
    CallSite,
    FunctionIR,
    ProjectIR,
    extract_python,
)


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_decorators_are_extracted(tmp_path: Path):
    p = _write(
        tmp_path,
        "app.py",
        "@app.route('/hello')\n"
        "@login_required\n"
        "def handler():\n"
        "    return 'hi'\n",
    )
    ir = extract_python(p)
    assert len(ir.functions) == 1
    fn = ir.functions[0]
    assert fn.name == "handler"
    assert any("app.route" in d for d in fn.decorators)
    assert "login_required" in fn.decorators


def test_conditionals_loops_and_exceptions_recorded(tmp_path: Path):
    p = _write(
        tmp_path,
        "ctl.py",
        "def process(flag):\n"
        "    if flag:\n"
        "        return 1\n"
        "    elif flag == 2:\n"
        "        return 2\n"
        "    for i in range(10):\n"
        "        print(i)\n"
        "    while True:\n"
        "        break\n"
        "    try:\n"
        "        risky()\n"
        "    except ValueError:\n"
        "        pass\n",
    )
    ir = extract_python(p)
    fn = ir.functions[0]
    # if + elif recorded as two conditionals
    assert len(fn.conditionals) == 2
    assert fn.conditionals[0]["condition_text"] == "flag"
    assert fn.conditionals[1]["condition_text"] == "flag == 2"
    # for + while loops
    loop_types = [l["type"] for l in fn.loops]
    assert loop_types == ["for", "while"]
    # try/except
    assert len(fn.exceptions) == 1
    assert fn.exceptions[0]["caught_exceptions"] == ["ValueError"]
    # return expressions
    assert "1" in fn.returns
    assert "2" in fn.returns


def test_imports_recorded_at_project_level(tmp_path: Path):
    p = _write(
        tmp_path,
        "imp.py",
        "import os\n"
        "from flask import request\n"
        "def handler():\n"
        "    pass\n",
    )
    ir = extract_python(p)
    assert any("import os" in imp for imp in ir.imports)
    assert any("from flask import request" in imp for imp in ir.imports)


def test_class_and_methods_extracted(tmp_path: Path):
    p = _write(
        tmp_path,
        "cls.py",
        "class Base:\n"
        "    pass\n"
        "class Handler(Base):\n"
        "    def get(self):\n"
        "        return 1\n"
        "    def post(self):\n"
        "        return 2\n",
    )
    ir = extract_python(p)
    assert len(ir.classes) == 2
    handler_cls = next(c for c in ir.classes if c["name"] == "Handler")
    assert "Base" in handler_cls["bases"]
    assert set(handler_cls["methods"]) == {"get", "post"}
    # methods carry the class_name
    get_fn = next(f for f in ir.functions if f.name == "get")
    assert get_fn.class_name == "Handler"
    assert get_fn.qualified_name == "Handler.get"


def test_backward_compatible_fields_unchanged(tmp_path: Path):
    p = _write(
        tmp_path,
        "bc.py",
        "def handler(user_id):\n"
        "    value = request.args.get('id')\n"
        "    return execute(value)\n",
    )
    ir = extract_python(p)
    fn = ir.functions[0]
    # original fields must still behave exactly as before
    assert fn.name == "handler"
    assert fn.qualified_name == "handler"
    assert fn.parameters == ["user_id"]
    assert "request.args" in fn.sources
    assert any(call.name == "execute" for call in fn.calls)
    assert "value" in fn.assignments
    # new fields exist with safe defaults
    assert fn.decorators == []
    assert fn.conditionals == []
    assert fn.loops == []
    assert fn.exceptions == []
    assert fn.class_name == ""


def test_projectir_defaults_and_dump(tmp_path: Path):
    p = _write(tmp_path, "simple.py", "def f():\n    pass\n")
    ir = extract_python(p)
    assert isinstance(ir, ProjectIR)
    assert isinstance(ir.functions[0], FunctionIR)
    assert ir.functions[0].calls == []
    dumped = ir.dump_json()
    assert "functions" in dumped
    assert "imports" in dumped
    assert "classes" in dumped
