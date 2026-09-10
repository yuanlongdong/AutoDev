"""Conservative intraprocedural taint analysis for authorized source review.

This module never executes target code. It proves only simple local source-to-sink
flows and intentionally leaves interprocedural/complex control-flow cases unknown.
"""
from dataclasses import dataclass, field
from pathlib import Path
import ast
from typing import Dict, List, Set


PY_SOURCES = {
    "input",
    "sys.argv",
    "os.environ",
}
PY_SOURCE_PREFIXES = (
    "request.args", "request.form", "request.json", "request.values",
    "request.data", "request.query_params",
)
PY_SINKS = {
    "cursor.execute", "cursor.executemany", "connection.execute",
    "db.execute", "execute", "executemany",
    "os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen",
    "eval", "exec", "open", "requests.get", "requests.post", "requests.request",
}
# Only transformations with a known security-relevant meaning are listed.
PY_SQL_SAFE_NAMES = {"sqlalchemy.text", "sqlite3.Connection.execute"}


@dataclass
class TaintPath:
    source: str
    sink: str
    line: int
    expression: str
    sanitizer: str = "UNKNOWN"
    steps: List[str] = field(default_factory=list)


class _Analyzer(ast.NodeVisitor):
    def __init__(self):
        self.tainted: Set[str] = set()
        self.paths: List[TaintPath] = []
        self.sinks_seen: List[tuple] = []
        self.source_for: Dict[str, str] = {}

    @staticmethod
    def _name(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parts = []
            cur = node
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
                return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _text(node):
        try:
            return ast.unparse(node)
        except Exception:
            return "<expr>"

    def _is_source(self, node):
        name = self._name(node)
        if name in PY_SOURCES or any(name.startswith(p) for p in PY_SOURCE_PREFIXES):
            return name
        if isinstance(node, ast.Call) and self._name(node.func) == "input":
            return "input()"
        if isinstance(node, ast.Subscript):
            base = self._name(node.value)
            if base in PY_SOURCES or any(base.startswith(p) for p in PY_SOURCE_PREFIXES):
                return base
        return ""

    def _contains_taint(self, node):
        source = self._is_source(node)
        if source:
            return source
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return self.source_for.get(node.id, node.id)
        for child in ast.iter_child_nodes(node):
            found = self._contains_taint(child)
            if found:
                return found
        return ""

    def visit_Assign(self, node):
        source = self._contains_taint(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if source:
                    self.tainted.add(target.id)
                    self.source_for[target.id] = source
                else:
                    self.tainted.discard(target.id)
                    self.source_for.pop(target.id, None)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        source = self._contains_taint(node.value) if node.value else ""
        if isinstance(node.target, ast.Name):
            if source:
                self.tainted.add(node.target.id)
                self.source_for[node.target.id] = source
            else:
                self.tainted.discard(node.target.id)
                self.source_for.pop(node.target.id, None)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self._name(node.func)
        if name in PY_SINKS or any(name.endswith("." + x.split(".")[-1]) for x in PY_SINKS if "." in x):
            for arg in node.args:
                source = self._contains_taint(arg)
                if source:
                    sanitizer = "UNKNOWN"
                    # Parameterized SQL calls with separate arguments are not treated
                    # as proof of injection; concatenated/format-built expressions are.
                    if name.endswith("execute") and len(node.args) >= 2:
                        continue
                    self.paths.append(TaintPath(
                        source=source,
                        sink=name,
                        line=node.lineno,
                        expression=self._text(arg),
                        sanitizer=sanitizer,
                        steps=[source, self._text(arg), name],
                    ))
        self.generic_visit(node)


def analyze_python_taint(path: Path) -> List[TaintPath]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except (OSError, SyntaxError):
        return []
    analyzer = _Analyzer()
    analyzer.visit(tree)
    unique = []
    seen = set()
    for path_item in analyzer.paths:
        key = (path_item.source, path_item.sink, path_item.line, path_item.expression)
        if key not in seen:
            seen.add(key)
            unique.append(path_item)
    return unique
