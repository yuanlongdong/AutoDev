"""Lightweight control-flow graph (CFG) construction from AST facts.

This builds a *simplified* CFG: basic blocks are line-range segments split at
the branch points recorded on :class:`~vulnresearch.ir.FunctionIR` (if/elif,
loops, try/except, early returns).  Edges model linear fall-through, the
true/false branches of conditionals, loop back-edges and exception handlers.
No SSA is built — only blocks and edges, as required for reachability and
counter-evidence checks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set

from .ir import FunctionIR


@dataclass
class BasicBlock:
    """A straight-line sequence of statements with a single entry and exit."""

    id: int
    start_line: int
    end_line: int
    statements: List[str] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)


@dataclass
class ControlFlowGraph:
    """A function-level control-flow graph."""

    blocks: List[BasicBlock] = field(default_factory=list)
    entry_block: int = 0
    function_name: str = ""


class CFGBuilder:
    """Construct a :class:`ControlFlowGraph` from a :class:`FunctionIR`."""

    def build(self, function_ir: FunctionIR, source_lines: List[str]) -> ControlFlowGraph:
        start = function_ir.line
        end = function_ir.end_line

        # -- collect every line where control flow may split ----------------
        breakpoints: Set[int] = {start}
        for cond in function_ir.conditionals:
            breakpoints.add(int(cond["line"]))
        for loop in function_ir.loops:
            breakpoints.add(int(loop["line"]))
        for exc in function_ir.exceptions:
            breakpoints.add(int(exc["line"]))

        return_lines: Set[int] = set()
        for idx in range(start - 1, min(end, len(source_lines))):
            if source_lines[idx].strip().startswith("return"):
                lineno = idx + 1
                breakpoints.add(lineno)
                return_lines.add(lineno)

        sorted_bp = sorted(b for b in breakpoints if b > 0)

        # -- split the function into contiguous blocks ----------------------
        blocks: List[BasicBlock] = []
        for i, bp in enumerate(sorted_bp):
            bstart = bp
            bend = sorted_bp[i + 1] - 1 if i + 1 < len(sorted_bp) else end
            statements: List[str] = []
            for lineno in range(bstart, bend + 1):
                if 1 <= lineno <= len(source_lines):
                    statements.append(source_lines[lineno - 1].rstrip())
            blocks.append(BasicBlock(
                id=i,
                start_line=bstart,
                end_line=bend,
                statements=statements,
            ))

        def block_containing(line: int) -> int:
            bidx = 0
            for i, bp in enumerate(sorted_bp):
                if bp <= line:
                    bidx = i
                else:
                    break
            return bidx

        # -- terminal blocks: a return ends the block's fall-through --------
        terminal: Set[int] = set()
        for blk in blocks:
            for lineno in range(blk.start_line, blk.end_line + 1):
                if lineno in return_lines:
                    terminal.add(blk.id)
                    break

        # -- linear fall-through edges --------------------------------------
        for i in range(len(blocks) - 1):
            if i in terminal:
                continue
            blocks[i].successors.append(i + 1)
            blocks[i + 1].predecessors.append(i)

        # -- conditional branch: decision block also skips to the join ------
        for cond in function_ir.conditionals:
            b = block_containing(int(cond["line"]))
            if b + 2 < len(blocks) and (b + 2) not in blocks[b].successors:
                blocks[b].successors.append(b + 2)
                blocks[b + 2].predecessors.append(b)

        # -- loop: back edge from the body block back to the loop header -----
        for loop in function_ir.loops:
            b = block_containing(int(loop["line"]))
            if b + 1 < len(blocks):
                blocks[b + 1].successors.append(b)
                blocks[b].predecessors.append(b + 1)

        # -- try/except: try block also branches to the except handler ------
        for exc in function_ir.exceptions:
            b = block_containing(int(exc["line"]))
            if b + 2 < len(blocks) and (b + 2) not in blocks[b].successors:
                blocks[b].successors.append(b + 2)
                blocks[b + 2].predecessors.append(b)

        return ControlFlowGraph(
            blocks=blocks,
            entry_block=0,
            function_name=function_ir.name,
        )


def reachable_blocks(cfg: ControlFlowGraph, start: int) -> Set[int]:
    """Return the set of block ids reachable from ``start``."""
    seen: Set[int] = set()
    if not cfg.blocks:
        return seen
    stack: List[int] = [start]
    while stack:
        node = stack.pop()
        if node in seen or not (0 <= node < len(cfg.blocks)):
            continue
        seen.add(node)
        for succ in cfg.blocks[node].successors:
            if succ not in seen:
                stack.append(succ)
    return seen


def has_security_check_in_path(cfg: ControlFlowGraph, check_pattern: str) -> bool:
    """Check whether any reachable block from the entry contains ``check_pattern``.

    Used as counter-evidence: if a security check (e.g. ``is_admin``) appears
    on every path to a sink, the finding can be downgraded.
    """
    if not cfg.blocks:
        return False
    reachable = reachable_blocks(cfg, cfg.entry_block)
    for bid in reachable:
        for stmt in cfg.blocks[bid].statements:
            if check_pattern in stmt:
                return True
    return False
