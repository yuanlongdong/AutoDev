"""Unified structural analysis facade for the vulnerability researcher."""
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from .ast_engine import ASTResearchEngine
from .cfg import FunctionCFG, build_python_cfgs
from .graph import CallGraph, build_call_graph
from .ir import ProjectIR


@dataclass
class ProgramModel:
    """Parsed program model used by later evidence/data-flow passes."""

    ir: ProjectIR
    call_graph: CallGraph
    cfgs: Dict[str, List[FunctionCFG]]


class ProgramAnalyzer:
    """Build AST/IR, call graph, and per-file Python CFGs without execution."""

    def __init__(self, root: str, max_files: int = 10000):
        self.root = Path(root).resolve()
        self.max_files = max_files

    def run(self) -> ProgramModel:
        ir = ASTResearchEngine(str(self.root), max_files=self.max_files).run()
        graph = build_call_graph(ir)
        cfgs: Dict[str, List[FunctionCFG]] = {}
        seen = set()
        for fn in ir.functions:
            if fn.path in seen:
                continue
            seen.add(fn.path)
            path = Path(fn.path)
            if path.suffix.lower() == ".py":
                cfgs[fn.path] = build_python_cfgs(path)
        return ProgramModel(ir=ir, call_graph=graph, cfgs=cfgs)
