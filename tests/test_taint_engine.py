"""Tests for the PHASE 2 taint propagation engine."""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import ProjectIR, extract_python
from vulnresearch.dataflow import DataFlowAnalyzer
from vulnresearch.callgraph import CallGraphBuilder
from vulnresearch.taint_engine import (
    TaintEngine,
    TaintFlow,
    build_data_flow_steps,
)


def _extract(tmp_path: Path, files: dict):
    functions, imports, classes = [], [], []
    for name, src in files.items():
        p = tmp_path / name
        p.write_text(src, encoding="utf-8")
        ir = extract_python(p)
        functions.extend(ir.functions)
        imports.extend(ir.imports)
        classes.extend(ir.classes)
    return ProjectIR(functions, imports=imports, classes=classes)


def _intra_flows(tmp_path: Path, src: str, fn_name: str = "handler"):
    proj = _extract(tmp_path, {"app.py": src})
    fn = next(f for f in proj.functions if f.name == fn_name)
    lines = (tmp_path / "app.py").read_text(encoding="utf-8").splitlines()
    df = DataFlowAnalyzer().analyze(fn, lines)
    return TaintEngine().analyze_function(fn, df, lines), fn


def test_source_to_sink_flow(tmp_path: Path):
    flows, _ = _intra_flows(tmp_path,
        "def handler():\n"
        "    cmd = request.args.get('cmd')\n"
        "    os.system(cmd)\n",
    )
    assert len(flows) == 1
    flow = flows[0]
    assert "request.args" in flow.source
    assert flow.sink == "os.system"
    assert flow.sanitized is False
    # the path contains source, transform and sink steps
    steps = build_data_flow_steps(flow)
    assert steps[0].step == "source"
    assert any(s.step == "sink" for s in steps)
    assert any("cmd" in s.transformation for s in steps)


def test_flow_through_sanitizer_is_marked(tmp_path: Path):
    flows, _ = _intra_flows(tmp_path,
        "def handler():\n"
        "    cmd = request.args.get('cmd')\n"
        "    safe = escape(cmd)\n"
        "    os.system(safe)\n",
    )
    assert len(flows) == 1
    flow = flows[0]
    assert flow.sink == "os.system"
    # escape() is a known sanitizer -> flow flagged as sanitized
    assert flow.sanitized is True


def test_no_flow_when_sink_not_reached(tmp_path: Path):
    flows, _ = _intra_flows(tmp_path,
        "def handler():\n"
        "    cmd = request.args.get('cmd')\n"
        "    safe = escape(cmd)\n"
        "    render(safe)\n",
    )
    # render is not a sink, so no taint flow is emitted
    assert flows == []


def test_cross_function_propagation(tmp_path: Path):
    proj = _extract(tmp_path, {"app.py":
        "def entry():\n"
        "    cmd = request.args.get('cmd')\n"
        "    run(cmd)\n"
        "def run(q):\n"
        "    os.system(q)\n",
    })
    cg = CallGraphBuilder().build(proj)
    flows = TaintEngine().analyze_project(proj, cg)
    # the sink lives in run(q); taint arrives from entry via parameter passing
    assert any(f.sink == "os.system" for f in flows)
    flow = next(f for f in flows if f.sink == "os.system")
    assert "request.args" in flow.source
