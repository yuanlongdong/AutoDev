from pathlib import Path
from vulnresearch.ast_engine import ASTResearchEngine


def test_python_ast_builds_function_and_call_graph_seed(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "def handler(user_id):\n"
        "    value = request.args.get('id')\n"
        "    return execute(value)\n",
        encoding="utf-8",
    )
    ir = ASTResearchEngine(str(tmp_path)).run()
    assert len(ir.functions) == 1
    fn = ir.functions[0]
    assert fn.name == "handler"
    assert "execute" in [call.name for call in fn.calls]
    assert "request.args" in fn.sources


def test_syntax_error_is_safe(tmp_path: Path):
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    assert ASTResearchEngine(str(tmp_path)).run().functions == []
