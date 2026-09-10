"""Lightweight language-neutral intermediate representation for source research.

This module deliberately avoids executing target code. It extracts functions,
call sites, assignments and simple source/sink signals so later passes can
reason about reachability and evidence without relying on regex-only findings.

PHASE 2 extensions add control-flow facts (decorators, returns, conditionals,
loops, exceptions), module-level imports and class definitions while keeping
the original ``FunctionIR`` / ``CallSite`` / ``ProjectIR`` fields and method
signatures unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
import ast
import json
import re
from typing import Dict, List, Optional


@dataclass
class CallSite:
    """A single call expression inside a function."""

    name: str
    line: int
    column: int = 0
    args: List[str] = field(default_factory=list)


@dataclass
class FunctionIR:
    """Intermediate representation of a single function definition."""

    name: str
    qualified_name: str
    path: str
    line: int
    end_line: int
    parameters: List[str] = field(default_factory=list)
    calls: List[CallSite] = field(default_factory=list)
    assignments: List[str] = field(default_factory=list)
    # Full assignment expressions ``"lhs = rhs"`` (v0.2.2) so downstream
    # detectors can perform lightweight source/sink taint tracking without
    # re-parsing source.  Defaulted for backward compatibility.
    assignment_exprs: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)
    # --- PHASE 2 extensions (new fields, all defaulted for back-compat) ---
    decorators: List[str] = field(default_factory=list)
    returns: List[str] = field(default_factory=list)
    conditionals: List[dict] = field(default_factory=list)
    loops: List[dict] = field(default_factory=list)
    exceptions: List[dict] = field(default_factory=list)
    class_name: str = ""


@dataclass
class ProjectIR:
    """Intermediate representation of an entire analysed project."""

    functions: List[FunctionIR] = field(default_factory=list)
    # --- PHASE 2 extensions ---
    imports: List[str] = field(default_factory=list)
    classes: List[dict] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)

    def dump_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


def _call_name(node: ast.Call) -> str:
    """Return a dotted name for the called function (``mod.func`` or ``obj.attr``)."""
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
    r"(?:request\.(?:args|form|json|values|data|query_params|get|post|body|files|cookies|headers)|"
    r"sys\.argv|input\s*\(|os\.environ)", re.I
)
PY_SINK_NAMES = {
    "os.system", "os.popen", "subprocess.run", "subprocess.call", "subprocess.Popen",
    "eval", "exec", "pickle.load", "pickle.loads", "yaml.load",
    "open", "requests.get", "requests.post", "requests.request",
}


class _PythonExtractor(ast.NodeVisitor):
    """AST visitor that builds :class:`FunctionIR` objects without executing code."""

    def __init__(self, path: str):
        self.path = path
        self.functions: List[FunctionIR] = []
        self._stack: List[FunctionIR] = []
        # PHASE 2 state
        self.current_class: str = ""
        self.imports: List[str] = []
        self.classes: List[dict] = []

    # -- function / method handling ----------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_function(node)

    def _visit_function(self, node):
        parent = self._stack[-1].qualified_name if self._stack else ""
        # Methods directly inside a class are qualified against the class name.
        if not parent and self.current_class:
            parent = self.current_class
        qualified = f"{parent}.{node.name}" if parent else node.name
        params = [a.arg for a in node.args.args]
        decorators: List[str] = []
        for dec in node.decorator_list:
            try:
                decorators.append(ast.unparse(dec))
            except Exception:
                decorators.append("<decorator>")
        fn = FunctionIR(
            name=node.name,
            qualified_name=qualified,
            path=self.path,
            line=node.lineno,
            end_line=getattr(node, "end_lineno", node.lineno),
            parameters=params,
            decorators=decorators,
            class_name=self.current_class,
        )
        self.functions.append(fn)
        self._stack.append(fn)
        for child in node.body:
            self.visit(child)
        self._stack.pop()

    # -- class handling ----------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef):
        bases: List[str] = []
        for base in node.bases:
            try:
                bases.append(ast.unparse(base))
            except Exception:
                bases.append("<base>")
        methods = [
            n.name
            for n in node.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self.classes.append({
            "name": node.name,
            "line": node.lineno,
            "methods": methods,
            "bases": bases,
        })
        prev_class = self.current_class
        self.current_class = node.name
        for child in node.body:
            self.visit(child)
        self.current_class = prev_class

    # -- existing call / assignment logic (preserved) ----------------------

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
        # Also capture keyword arguments (e.g. shell=True, algorithm='none')
        # so detectors can reason about them without re-parsing source lines.
        for kw in node.keywords:
            if kw.arg is None:
                continue  # **kwargs unpacking — skip
            try:
                args.append(f"{kw.arg}={ast.unparse(kw.value)}")
            except Exception:
                pass
        call = CallSite(name=name, line=node.lineno, column=node.col_offset, args=args)
        fn = self._stack[-1]
        fn.calls.append(call)
        m = PY_SOURCE_PATTERNS.search(name)
        if m:
            fn.sources.append(m.group(0).rstrip("(").rstrip())
        if name in PY_SINK_NAMES or any(name.startswith(x + ".") for x in PY_SINK_NAMES):
            fn.sinks.append(name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        if self._stack:
            rhs_text = ""
            try:
                rhs_text = ast.unparse(node.value)
            except Exception:
                rhs_text = ""
            for target in node.targets:
                try:
                    lhs = ast.unparse(target)
                    self._stack[-1].assignments.append(lhs)
                    if rhs_text:
                        # v0.2.2: keep the full "lhs = rhs" for taint tracking.
                        self._stack[-1].assignment_exprs.append(f"{lhs} = {rhs_text}")
                except Exception:
                    pass
        self.generic_visit(node)

    # -- PHASE 2 control-flow visitors -------------------------------------

    def visit_If(self, node: ast.If):
        """Record ``if`` / ``elif`` conditions, then recurse into body."""
        if self._stack:
            try:
                cond_text = ast.unparse(node.test)
            except Exception:
                cond_text = "<cond>"
            self._stack[-1].conditionals.append({
                "line": node.lineno,
                "condition_text": cond_text,
            })
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        if self._stack:
            self._stack[-1].loops.append({"line": node.lineno, "type": "for"})
        self.generic_visit(node)

    def visit_While(self, node: ast.While):
        if self._stack:
            self._stack[-1].loops.append({"line": node.lineno, "type": "while"})
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try):
        if self._stack:
            caught: List[str] = []
            for handler in node.handlers:
                if handler.type is None:
                    caught.append("BaseException")
                else:
                    try:
                        caught.append(ast.unparse(handler.type))
                    except Exception:
                        caught.append("Exception")
            self._stack[-1].exceptions.append({
                "line": node.lineno,
                "caught_exceptions": caught,
            })
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return):
        if self._stack:
            if node.value is not None:
                try:
                    self._stack[-1].returns.append(ast.unparse(node.value))
                except Exception:
                    self._stack[-1].returns.append("<expr>")
            else:
                self._stack[-1].returns.append("")
        self.generic_visit(node)

    # -- import collection -------------------------------------------------

    def visit_Import(self, node: ast.Import):
        try:
            self.imports.append(ast.unparse(node))
        except Exception:
            pass
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        try:
            self.imports.append(ast.unparse(node))
        except Exception:
            pass
        self.generic_visit(node)


def extract_python(path: Path) -> ProjectIR:
    """Parse a single Python file into a :class:`ProjectIR`."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(text, filename=str(path))
    except (OSError, SyntaxError):
        return ProjectIR()
    visitor = _PythonExtractor(str(path))
    visitor.visit(tree)
    return ProjectIR(
        visitor.functions,
        imports=list(visitor.imports),
        classes=list(visitor.classes),
    )


def extract_file(path: Path) -> ProjectIR:
    """Dispatch extraction based on file suffix."""
    if path.suffix.lower() == ".py":
        return extract_python(path)
    return ProjectIR()
