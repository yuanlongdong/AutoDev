"""Tests for the PHASE 2 cross-function call graph."""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import ProjectIR, extract_python
from vulnresearch.callgraph import (
    CallGraph,
    CallGraphBuilder,
    entry_points,
    find_paths_to_sink,
    reachable_from,
)


def _build(tmp_path: Path, files: dict) -> CallGraph:
    functions, imports, classes = [], [], []
    for name, src in files.items():
        p = tmp_path / name
        p.write_text(src, encoding="utf-8")
        ir = extract_python(p)
        functions.extend(ir.functions)
        imports.extend(ir.imports)
        classes.extend(ir.classes)
    return CallGraphBuilder().build(ProjectIR(functions, imports=imports, classes=classes))


def test_callgraph_builds_edges(tmp_path: Path):
    cg = _build(tmp_path, {"m.py":
        "def main():\n"
        "    helper()\n"
        "def helper():\n"
        "    sink()\n"
        "def sink():\n"
        "    pass\n"
    })
    assert "main" in cg.nodes
    assert set(cg.edges["main"]) == {"helper"}
    assert set(cg.edges["helper"]) == {"sink"}
    # built-ins / unknown calls have no edge
    assert cg.edges["sink"] == []


def test_reachable_from_entry(tmp_path: Path):
    cg = _build(tmp_path, {"m.py":
        "def main():\n"
        "    helper()\n"
        "def helper():\n"
        "    sink()\n"
        "def sink():\n"
        "    pass\n"
    })
    reach = reachable_from(cg, "main")
    assert reach == {"main", "helper", "sink"}
    # from sink, nothing further
    assert reachable_from(cg, "sink") == {"sink"}


def test_entry_points_recognise_routers_and_uncalled(tmp_path: Path):
    cg = _build(tmp_path, {"m.py":
        "@app.route('/login')\n"
        "def login():\n"
        "    do_auth()\n"
        "def do_auth():\n"
        "    pass\n"
        "def internal():\n"
        "    pass\n"
    })
    eps = entry_points(cg)
    assert "login" in eps          # router-decorated
    assert "internal" in eps       # no caller, public
    assert "do_auth" not in eps   # called, so not an entry point


def test_find_paths_to_sink(tmp_path: Path):
    cg = _build(tmp_path, {"m.py":
        "def a():\n"
        "    b()\n"
        "def b():\n"
        "    sink()\n"
        "def sink():\n"
        "    pass\n"
    })
    paths = find_paths_to_sink(cg, "sink")
    assert ["a", "b", "sink"] in paths
    assert ["b", "sink"] in paths
    # every path ends at the sink
    assert all(p[-1] == "sink" for p in paths)


def test_recursion_does_not_loop_forever(tmp_path: Path):
    cg = _build(tmp_path, {"m.py":
        "def rec(n):\n"
        "    if n > 0:\n"
        "        rec(n - 1)\n"
    })
    reach = reachable_from(cg, "rec")
    assert reach == {"rec"}
    paths = find_paths_to_sink(cg, "rec")
    # should terminate; no infinite recursion
    assert isinstance(paths, list)
