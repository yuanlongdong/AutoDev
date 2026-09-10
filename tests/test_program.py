from pathlib import Path

from vulnresearch.program import ProgramAnalyzer


def test_program_analyzer_builds_ir_graph_and_cfg(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "def helper(value):\n"
        "    return value\n\n"
        "def handler(value):\n"
        "    if value:\n"
        "        return helper(value)\n"
        "    return helper('fallback')\n",
        encoding="utf-8",
    )
    model = ProgramAnalyzer(str(tmp_path)).run()
    assert len(model.ir.functions) == 2
    assert any(edge.caller == "handler" and edge.callee == "helper" for edge in model.call_graph.edges)
    assert str(tmp_path / "app.py") in model.cfgs
    assert model.cfgs[str(tmp_path / "app.py")]
