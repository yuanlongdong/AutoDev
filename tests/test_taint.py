from pathlib import Path

from vulnresearch.taint import analyze_python_taint
from vulnresearch.engine import ResearchEngine


def test_direct_request_to_execute_is_e2(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text(
        "def handler(request, cursor):\n"
        "    query = request.args.get('q')\n"
        "    cursor.execute(query)\n",
        encoding="utf-8",
    )
    flows = analyze_python_taint(path)
    assert len(flows) == 1
    assert flows[0].source == "request.args.get"
    assert flows[0].sink == "cursor.execute"

    findings = ResearchEngine(str(tmp_path)).run()
    taint = [f for f in findings if f.category == "taint-flow"]
    assert len(taint) == 1
    assert taint[0].evidence_level == "E2"
    assert taint[0].status == "likely"
    assert taint[0].confidence == "Medium"
    assert taint[0].severity == "High"


def test_alias_propagation_is_detected(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text(
        "def handler(request, cursor):\n"
        "    raw = request.form['name']\n"
        "    query = raw\n"
        "    cursor.execute(query)\n",
        encoding="utf-8",
    )
    flows = analyze_python_taint(path)
    assert len(flows) == 1
    assert flows[0].source == "request.form"


def test_parameterized_execute_is_not_reported_as_injection_flow(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text(
        "def handler(request, cursor):\n"
        "    value = request.args.get('id')\n"
        "    cursor.execute('select * from users where id = ?', (value,))\n",
        encoding="utf-8",
    )
    assert analyze_python_taint(path) == []


def test_unrelated_source_and_sink_are_not_joined(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text(
        "def handler(request, cursor):\n"
        "    value = request.args.get('id')\n"
        "    cursor.execute('select 1')\n",
        encoding="utf-8",
    )
    assert analyze_python_taint(path) == []


def test_cross_function_flow_remains_unknown(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text(
        "def get_value(request):\n"
        "    return request.args.get('id')\n\n"
        "def handler(request, cursor):\n"
        "    value = get_value(request)\n"
        "    cursor.execute(value)\n",
        encoding="utf-8",
    )
    assert analyze_python_taint(path) == []
