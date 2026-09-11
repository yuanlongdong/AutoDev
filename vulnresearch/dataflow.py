"""Intra-procedural data-flow analysis: definitions, uses and def-use chains.

The analyser is deliberately static: it parses supplied source text and never
imports, executes, or contacts the target project.  Taint is conservative and
transitive within one function, while respecting the latest definition before
the point being queried.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .ir import FunctionIR
from .knowledge_base import SOURCE_TOKENS

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class Definition:
    """A variable assignment at a specific line."""

    var_name: str
    line: int
    expression: str = ""


@dataclass
class Use:
    """A variable reference at a specific line, with a short context note."""

    var_name: str
    line: int
    context: str = ""


@dataclass
class DataFlowResult:
    """Outcome of data-flow analysis for one function."""

    definitions: List[Definition] = field(default_factory=list)
    uses: List[Use] = field(default_factory=list)
    def_use_chains: Dict[str, List[Use]] = field(default_factory=dict)


class DataFlowAnalyzer:
    """Build definitions / uses / def-use chains for a single function."""

    def analyze(self, function_ir: FunctionIR, source_lines: List[str]) -> DataFlowResult:
        definitions: List[Definition] = []
        uses: List[Use] = []

        fn_node = self._find_function(function_ir, source_lines)
        if fn_node is not None:
            for node in ast.walk(fn_node):
                if isinstance(node, ast.Assign):
                    rhs = self._unparse(node.value)
                    for target in node.targets:
                        self._collect_definition(target, node.lineno, rhs, definitions)
                elif isinstance(node, ast.AnnAssign):
                    if isinstance(node.target, ast.Name):
                        rhs = self._unparse(node.value) if node.value is not None else ""
                        definitions.append(Definition(node.target.id, node.lineno, rhs))
                elif isinstance(node, ast.AugAssign):
                    if isinstance(node.target, ast.Name):
                        definitions.append(
                            Definition(node.target.id, node.lineno, self._unparse(node.value))
                        )
                elif isinstance(node, ast.Call):
                    call_name = self._call_name(node)
                    for arg in node.args:
                        for name in self._load_names(arg):
                            uses.append(Use(name, node.lineno, context=f"call:{call_name}"))
                    for kw in node.keywords:
                        for name in self._load_names(kw.value):
                            uses.append(Use(name, node.lineno, context=f"call:{call_name}"))
                elif isinstance(node, ast.Return) and node.value is not None:
                    for name in self._load_names(node.value):
                        uses.append(Use(name, node.lineno, context="return"))

        chains: Dict[str, List[Use]] = {}
        for defn in definitions:
            chains.setdefault(defn.var_name, [])
        for use in uses:
            if use.var_name in chains:
                chains[use.var_name].append(use)

        return DataFlowResult(definitions=definitions, uses=uses, def_use_chains=chains)

    @staticmethod
    def _unparse(node: Optional[ast.AST]) -> str:
        if node is None:
            return ""
        try:
            return ast.unparse(node)
        except Exception:
            return "<expr>"

    @staticmethod
    def _call_name(node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts: List[str] = []
            cur = node.func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return "<dynamic>"

    @staticmethod
    def _load_names(node: ast.AST) -> List[str]:
        out: List[str] = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                out.append(child.id)
        return out

    @staticmethod
    def _collect_definition(target, lineno: int, rhs: str, out: List[Definition]) -> None:
        if isinstance(target, ast.Name):
            out.append(Definition(target.id, lineno, rhs))
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                if isinstance(elt, ast.Name):
                    out.append(Definition(elt.id, lineno, rhs))

    def _find_function(self, function_ir: FunctionIR, source_lines: List[str]):
        try:
            tree = ast.parse("\n".join(source_lines))
        except (SyntaxError, ValueError):
            return None
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.lineno == function_ir.line:
                    return node
        return None


def _normalise_source_tokens() -> Set[str]:
    """Return source markers in a form suitable for AST path matching."""
    return {token.rstrip("(") for token in SOURCE_TOKENS if token}


def _attribute_path(node: ast.AST) -> str:
    """Return a dotted AST path for ``request.args.get``-like expressions."""
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _contains_source_expression(expression: str) -> bool:
    """Detect a source expression without matching arbitrary string literals."""
    try:
        tree = ast.parse(expression, mode="eval")
    except (SyntaxError, ValueError):
        return False

    tokens = _normalise_source_tokens()
    for node in ast.walk(tree):
        candidates: List[str] = []
        if isinstance(node, ast.Call):
            candidates.append(_attribute_path(node.func))
            if isinstance(node.func, ast.Name):
                candidates.append(node.func.id)
        elif isinstance(node, ast.Attribute):
            candidates.append(_attribute_path(node))
        elif isinstance(node, ast.Name):
            candidates.append(node.id)
        for candidate in candidates:
            if not candidate:
                continue
            if any(candidate == token or candidate.startswith(token + ".") for token in tokens):
                return True
    return False


def is_tainted_at(variable: str, result: DataFlowResult, line: int) -> bool:
    """Return conservative taint status at ``line`` using transitive def-use data.

    Only definitions at or before ``line`` participate.  If a definition is
    derived from another variable, that dependency is followed recursively.
    Cycles are treated as unknown/non-tainted rather than looping forever.
    """
    visiting: Set[str] = set()
    cache: Dict[str, bool] = {}

    def resolve(name: str, before_line: int) -> bool:
        key = f"{name}@{before_line}"
        if key in cache:
            return cache[key]
        if key in visiting:
            return False
        visiting.add(key)

        candidates = [d for d in result.definitions if d.var_name == name and d.line <= before_line]
        if not candidates:
            visiting.discard(key)
            cache[key] = False
            return False
        definition = max(candidates, key=lambda d: d.line)

        tainted = _contains_source_expression(definition.expression)
        if not tainted:
            try:
                expr_tree = ast.parse(definition.expression, mode="eval")
            except (SyntaxError, ValueError):
                expr_tree = None
            if expr_tree is not None:
                deps = {
                    n.id for n in ast.walk(expr_tree)
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)
                }
                tainted = any(resolve(dep, definition.line - 1) for dep in deps if dep != name)

        visiting.discard(key)
        cache[key] = tainted
        return tainted

    return resolve(variable, line)


def is_tainted(variable: str, result: DataFlowResult, source_lines: List[str]) -> bool:
    """Return whether the latest definition of ``variable`` is transitively tainted.

    ``source_lines`` is retained for backward compatibility with the original
    API.  The analysis result already contains the parsed definition data.
    """
    del source_lines
    if not any(d.var_name == variable for d in result.definitions):
        return False
    latest_line = max(d.line for d in result.definitions if d.var_name == variable)
    return is_tainted_at(variable, result, latest_line)
