"""Tests for the PHASE 2 control-flow graph builder."""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.cfg import (
    CFGBuilder,
    ControlFlowGraph,
    has_security_check_in_path,
    reachable_blocks,
)


def _build(tmp_path: Path, src: str, fn_name: str = "f") -> ControlFlowGraph:
    p = tmp_path / "m.py"
    p.write_text(src, encoding="utf-8")
    ir = extract_python(p)
    fn = next(f for f in ir.functions if f.name == fn_name)
    return CFGBuilder().build(fn, src.splitlines())


def test_if_else_builds_decision_with_two_branches(tmp_path: Path):
    cfg = _build(tmp_path,
        "def f(flag):\n"
        "    if flag:\n"
        "        return 1\n"
        "    else:\n"
        "        return 2\n",
    )
    assert cfg.function_name == "f"
    # the decision block (the `if`) must have two successors: true & false
    decision = next(b for b in cfg.blocks if any("if flag" in s for s in b.statements))
    assert len(decision.successors) == 2
    # both returns are reachable from entry
    reach = reachable_blocks(cfg, cfg.entry_block)
    return_blocks = [b for b in cfg.blocks if any("return" in s for s in b.statements)]
    assert len(return_blocks) == 2
    assert all(b.id in reach for b in return_blocks)


def test_loop_has_back_edge(tmp_path: Path):
    cfg = _build(tmp_path,
        "def f():\n"
        "    total = 0\n"
        "    for i in range(10):\n"
        "        total += i\n"
        "    return total\n",
    )
    # find the loop-header block and confirm a back edge exists
    loop_header = next(
        b for b in cfg.blocks if any("for i in range" in s for s in b.statements)
    )
    has_back_edge = any(succ <= loop_header.id for succ in loop_header.successors) or any(
        loop_header.id in cfg.blocks[pred].successors
        for pred in loop_header.predecessors
    )
    assert has_back_edge, "loop should introduce a back edge"
    # loop body is reachable
    reach = reachable_blocks(cfg, cfg.entry_block)
    assert loop_header.id in reach
    assert len(cfg.blocks) >= 3


def test_early_return_terminates_block(tmp_path: Path):
    cfg = _build(tmp_path,
        "def f(flag):\n"
        "    if flag:\n"
        "        return 1\n"
        "    x = 2\n"
        "    return x\n",
    )
    early = next(b for b in cfg.blocks if any("return 1" in s for s in b.statements))
    # the early-return block must not fall through to later code
    assert early.successors == []
    # the code after the if is still reachable via the false branch
    reach = reachable_blocks(cfg, cfg.entry_block)
    later = next(b for b in cfg.blocks if any("x = 2" in s for s in b.statements))
    assert later.id in reach


def test_reachable_blocks_from_start(tmp_path: Path):
    cfg = _build(tmp_path,
        "def f(flag):\n"
        "    if flag:\n"
        "        return 1\n"
        "    return 2\n",
    )
    reach = reachable_blocks(cfg, cfg.entry_block)
    assert reach == set(range(len(cfg.blocks)))
    # starting from an unreachable-looking block still returns just itself+succs
    if len(cfg.blocks) > 1:
        sub = reachable_blocks(cfg, len(cfg.blocks) - 1)
        assert cfg.blocks[-1].id in sub


def test_has_security_check_in_path(tmp_path: Path):
    cfg = _build(tmp_path,
        "def f(flag):\n"
        "    if is_admin():\n"
        "        return 1\n"
        "    return 2\n",
    )
    assert has_security_check_in_path(cfg, "is_admin") is True
    assert has_security_check_in_path(cfg, "not_present_xyz") is False
