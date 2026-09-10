from pathlib import Path

from vulnresearch.ast_engine import ASTResearchEngine
from vulnresearch.cfg import build_python_cfgs
from vulnresearch.graph import build_call_graph


def test_call_graph_resolves_unique_local_function(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "def helper(value):\n"
        "    return value\n\n"
        "def handler(user_id):\n"
        "    return helper(user_id)\n",
        encoding="utf-8",
    )
    ir = ASTResearchEngine(str(tmp_path)).run()
    graph = build_call_graph(ir)
    assert any(e.caller == "handler" and e.callee == "helper" for e in graph.edges)


def test_call_graph_leaves_dynamic_call_unresolved(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "def handler(fn, value):\n"
        "    return fn(value)\n",
        encoding="utf-8",
    )
    ir = ASTResearchEngine(str(tmp_path)).run()
    graph = build_call_graph(ir)
    assert not graph.edges


def test_cfg_contains_if_branches_and_return_exit(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text(
        "def handler(value):\n"
        "    if value:\n"
        "        return 1\n"
        "    return 2\n",
        encoding="utf-8",
    )
    cfgs = build_python_cfgs(path)
    assert len(cfgs) == 1
    cfg = cfgs[0]
    assert any(edge.kind == "true" for edge in cfg.edges)
    assert len(cfg.exits) >= 2


def test_cfg_handles_loop_back_edge(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text(
        "def handler(items):\n"
        "    for item in items:\n"
        "        process(item)\n"
        "    return True\n",
        encoding="utf-8",
    )
    cfg = build_python_cfgs(path)[0]
    assert any(edge.kind == "loop" for edge in cfg.edges)
