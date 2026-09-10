"""Conservative local call-graph construction for authorized source review.

The graph is derived from the parsed IR only. It never imports or executes the
analyzed project. Only statically resolvable direct calls are connected; dynamic
calls remain unresolved rather than creating speculative edges.
"""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Tuple

from .ir import ProjectIR, FunctionIR, CallSite


@dataclass(frozen=True)
class CallGraphNode:
    qualified_name: str
    path: str
    line: int


@dataclass(frozen=True)
class CallGraphEdge:
    caller: str
    callee: str
    line: int


@dataclass
class CallGraph:
    nodes: List[CallGraphNode] = field(default_factory=list)
    edges: List[CallGraphEdge] = field(default_factory=list)
    unresolved: List[Tuple[str, str, int]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def build_call_graph(ir: ProjectIR) -> CallGraph:
    """Build a best-effort graph of functions defined in *ir*."""
    graph = CallGraph()
    by_qualified: Dict[str, FunctionIR] = {fn.qualified_name: fn for fn in ir.functions}
    by_name: Dict[str, List[FunctionIR]] = {}
    for fn in ir.functions:
        by_name.setdefault(fn.name, []).append(fn)
        graph.nodes.append(CallGraphNode(fn.qualified_name, fn.path, fn.line))

    seen_edges: Set[Tuple[str, str, int]] = set()
    seen_unresolved: Set[Tuple[str, str, int]] = set()

    for fn in ir.functions:
        for call in fn.calls:
            callee = _resolve(fn, call, by_qualified, by_name)
            if callee is None:
                if call.name != "<dynamic>":
                    item = (fn.qualified_name, call.name, call.line)
                    if item not in seen_unresolved:
                        graph.unresolved.append(item)
                        seen_unresolved.add(item)
                continue
            edge = (fn.qualified_name, callee.qualified_name, call.line)
            if edge not in seen_edges:
                graph.edges.append(CallGraphEdge(*edge))
                seen_edges.add(edge)
    return graph


def _resolve(
    caller: FunctionIR,
    call: CallSite,
    by_qualified: Dict[str, FunctionIR],
    by_name: Dict[str, List[FunctionIR]],
):
    if call.name == "<dynamic>" or "." in call.name:
        return by_qualified.get(call.name)

    # Prefer a function in the caller's lexical scope, then a unique project-wide
    # function. Ambiguous same-name functions are deliberately left unresolved.
    parent = caller.qualified_name.rsplit(".", 1)[0] if "." in caller.qualified_name else ""
    if parent:
        local = by_qualified.get(f"{parent}.{call.name}")
        if local:
            return local
    candidates = by_name.get(call.name, [])
    return candidates[0] if len(candidates) == 1 else None
