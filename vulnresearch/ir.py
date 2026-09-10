"""Lightweight language-neutral intermediate representation for source research.

This module deliberately avoids executing target code. It extracts functions,
call sites, assignments and simple source/sink signals so later passes can
reason about reachability and evidence without relying on regex-only findings.
"""
from dataclasses import dataclass, field, asdict
from pathlib import Path
import ast
import json
import re
from typing import List, Optional


@dataclass
class CallSite:
    name: str
    line: int
    column: int = 0
    args: List[str] = field(default_factory=list)


@dataclass
class FunctionIR:
    name: str
    qualified_name: str
    path: str
    line: int
    end_line: int
    parameters: List[str] = field(default_factory=list)
    calls: List[CallSite] = field(default_factory=list)
    assignments: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)


@dataclass
class ProjectIR:
    functions: List[FunctionIR] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    def dump_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        cur = node.func
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return "<dynamic>"


PY_SOURCE_PATTERNS = re.compile(
    r"(?:request\.(?:args|form|json|values|data|query_params)|"
    r"sys\.argv|input\s*\(|os\.environ)", re.I
)
PY_SINK_NAMES = {
    "os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen",
    "eval", "exec", "pickle.load", "pickle.loads", "yaml.load",
    "open", "requests.get", "requests.post", "requests.request",
}


class _PythonExtractor(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.functions: List[FunctionIR] = []
        self._stack: List[FunctionIR] = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_function(node)

    def _visit_function(self, node):
        parent = self._stack[-1].qualified_name if self._stack else ""
        qualified = f"{parent}.{node.name}" if parent else node.name
        params = [a.arg for a in node.args.args]
        fn = FunctionIR(
            name=node.name,
            qualified_name=qualified,
            path=self.path,
            line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            parameters=params,
        )
        self.functions.append(fn)
        self._stack.append(fn)
        for child in node.body:
            self.visit(child)
        self._stack.pop()

    def visit_Call(self, node: ast.Call):
        if not self._stack:
            return
        name = _call_name(node)
        args = []
        for arg in node.args:
            try:
                args.append(ast.unparse(arg))
            except Exception:
                args.append("<expr>")
        call = CallSite(name=name, line=node.lineno, column=node.col_offset, args=args)
        fn = self._stack[-1]
        fn.calls.append(call)
        if PY_SOURCE_PATTERNS.search(name):
            fn.sources.append(name)
        if name in PY_SINK_NAMES or any(name.startswith(x + ".") for x in PY_SINK_NAMES):
            fn.sinks.append(name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        if self._stack:
            for target in node.targets:
                try:
                    self._stack[-1].assignments.append(ast.unparse(target))
                except Exception:
                    pass
        self.generic_visit(node)


def extract_python(path: Path) -> ProjectIR:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text, filename=str(path))
    except (OSError, SyntaxError):
        return ProjectIR()
    visitor = _PythonExtractor(str(path))
    visitor.visit(tree)
    return ProjectIR(visitor.functions)


def extract_file(path: Path) -> ProjectIR:
    if path.suffix.lower() == ".py":
        return extract_python(path)
    return ProjectIR()
