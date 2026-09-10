"""Intra-procedural data-flow analysis: definitions, uses and def-use chains.

Definitions come from assignment statements (with line numbers and the
right-hand side expression); uses come from call arguments and return values.
The analyser rebuilds the function AST from the supplied source lines (it
never imports or executes the target project).  ``is_tainted`` checks whether
a variable's *most recent* definition derives from a source token.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set

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

        # -- def-use chains: variable -> the places it is used ---------------
        chains: Dict[str, List[Use]] = {}
        for defn in definitions:
            chains.setdefault(defn.var_name, [])
        for use in uses:
            if use.var_name in chains:
                chains[use.var_name].append(use)

        return DataFlowResult(definitions=definitions, uses=uses, def_use_chains=chains)

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def _unparse(node: ast.AST) -> str:
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
        """Collect ``Load``-context variable names referenced by an expression."""
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


def is_tainted(variable: str, result: DataFlowResult, source_lines: List[str]) -> bool:
    """Return ``True`` if the variable's most recent definition comes from a source.

    When a variable is assigned multiple times the definition with the largest
    line number (the nearest one) is consulted.
    """
    defs = [d for d in result.definitions if d.var_name == variable]
    if not defs:
        return False
    latest = max(defs, key=lambda d: d.line)
    expr = latest.expression
    return any(tok and tok in expr for tok in SOURCE_TOKENS)
