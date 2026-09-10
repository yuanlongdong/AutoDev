"""Conservative basic-block CFG builder for Python source.

This is structural analysis only. It does not execute target code and models
common control-flow constructs conservatively so later reachability analysis
can reason about possible paths without pretending to know runtime values.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import ast


@dataclass(frozen=True)
class BasicBlock:
    id: int
    statements: Tuple[str, ...]
    start_line: int
    end_line: int


@dataclass(frozen=True)
class CFGEdge:
    source: int
    target: int
    kind: str = "normal"


@dataclass
class FunctionCFG:
    name: str
    blocks: List[BasicBlock] = field(default_factory=list)
    edges: List[CFGEdge] = field(default_factory=list)
    entry: Optional[int] = None
    exits: Set[int] = field(default_factory=set)


class _Builder:
    def __init__(self):
        self.blocks: List[BasicBlock] = []
        self.edges: List[CFGEdge] = []

    def block(self, statements: List[ast.stmt]) -> int:
        if not statements:
            statements = []
        text = []
        for stmt in statements:
            try:
                text.append(ast.unparse(stmt))
            except Exception:
                text.append(type(stmt).__name__)
        lines = [getattr(s, "lineno", 0) for s in statements]
        end_lines = [getattr(s, "end_lineno", getattr(s, "lineno", 0)) for s in statements]
        idx = len(self.blocks)
        self.blocks.append(BasicBlock(idx, tuple(text), min(lines or [0]), max(end_lines or [0])))
        return idx

    def edge(self, source: int, target: int, kind: str = "normal") -> None:
        if source != target and CFGEdge(source, target, kind) not in self.edges:
            self.edges.append(CFGEdge(source, target, kind))


def build_function_cfg(node: ast.FunctionDef) -> FunctionCFG:
    """Build a conservative CFG for one Python function."""
    b = _Builder()
    entry = b.block([])
    cfg = FunctionCFG(node.name, b.blocks, b.edges, entry=entry)

    def sequence(stmts: List[ast.stmt], incoming: List[int]) -> List[int]:
        current = incoming[:]
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                cond = b.block([stmt])
                for src in current:
                    b.edge(src, cond)
                then_out = sequence(stmt.body, [cond])
                else_out = sequence(stmt.orelse, [cond]) if stmt.orelse else [cond]
                if stmt.orelse:
                    b.edge(cond, else_out[0], "false")
                else:
                    b.edge(cond, cond, "false") if False else None
                if then_out:
                    b.edge(cond, then_out[0], "true")
                current = then_out + else_out
            elif isinstance(stmt, (ast.For, ast.While)):
                head = b.block([stmt])
                for src in current:
                    b.edge(src, head)
                body_out = sequence(stmt.body, [head])
                for src in body_out:
                    b.edge(src, head, "loop")
                current = body_out + ([sequence(stmt.orelse, [head])[0]] if stmt.orelse else [head])
            elif isinstance(stmt, ast.Try):
                head = b.block([stmt])
                for src in current:
                    b.edge(src, head)
                body_out = sequence(stmt.body, [head])
                handler_out: List[int] = []
                for handler in stmt.handlers:
                    handler_out.extend(sequence(handler.body, [head]))
                current = body_out + handler_out
                if stmt.finalbody:
                    current = sequence(stmt.finalbody, current)
                elif stmt.orelse:
                    current = sequence(stmt.orelse, current)
            else:
                blk = b.block([stmt])
                for src in current:
                    b.edge(src, blk)
                if isinstance(stmt, (ast.Return, ast.Raise)):
                    cfg.exits.add(blk)
                    current = []
                elif isinstance(stmt, (ast.Break, ast.Continue)):
                    cfg.exits.add(blk)
                    current = []
                else:
                    current = [blk]
        return current

    tail = sequence(node.body, [entry])
    cfg.blocks = b.blocks
    cfg.edges = b.edges
    cfg.exits.update(tail)
    if not node.body:
        cfg.exits.add(entry)
    return cfg


def build_python_cfgs(path) -> List[FunctionCFG]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
    except (OSError, SyntaxError):
        return []
    return [build_function_cfg(node) for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
