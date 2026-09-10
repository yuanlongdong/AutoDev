"""Cross-function call-graph construction and reachability analysis.

The call graph is built from the call sites already recorded on each
:class:`~vulnresearch.ir.FunctionIR`.  Callees are matched by name (both
fully-qualified and short names, so ``handle(x)`` and ``self.handle(x)``
resolve to the same function).  Cycles are handled by visited-set tracking so
path finding terminates.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set

from .ir import FunctionIR, ProjectIR


@dataclass
class CallGraph:
    """A directed caller -> callee graph over function qualified names."""

    nodes: Dict[str, FunctionIR] = field(default_factory=dict)
    edges: Dict[str, List[str]] = field(default_factory=dict)


# Decorator substrings that mark a function as a web entry point / route.
_ROUTER_HINTS = {"route", "get", "post", "put", "delete", "patch", "handler", "on_request"}


class CallGraphBuilder:
    """Build a :class:`CallGraph` from a :class:`ProjectIR`."""

    def build(self, project_ir: ProjectIR) -> CallGraph:
        nodes: Dict[str, FunctionIR] = {}
        by_short_name: Dict[str, List[str]] = defaultdict(list)
        for fn in project_ir.functions:
            nodes[fn.qualified_name] = fn
            by_short_name[fn.name].append(fn.qualified_name)

        edges: Dict[str, List[str]] = {}
        for fn in project_ir.functions:
            callees: List[str] = []
            seen: Set[str] = set()
            for cs in fn.calls:
                target = self._resolve(cs.name, nodes, by_short_name)
                if target and target not in seen:
                    seen.add(target)
                    callees.append(target)
            edges[fn.qualified_name] = callees
        return CallGraph(nodes=nodes, edges=edges)

    @staticmethod
    def _resolve(
        call_name: str,
        nodes: Dict[str, FunctionIR],
        by_short_name: Dict[str, List[str]],
    ):
        """Resolve a call site name to a qualified function name, or ``None``."""
        if not call_name or call_name == "<dynamic>":
            return None
        # exact qualified match
        if call_name in nodes:
            return call_name
        # module.function / self.method -> match on the final identifier
        short = call_name.split(".")[-1]
        if short in by_short_name:
            candidates = by_short_name[short]
            if len(candidates) == 1:
                return candidates[0]
            # prefer a candidate whose qualified name ends with the call name
            for cand in candidates:
                if cand == call_name or cand.endswith("." + short):
                    return cand
            return candidates[0]
        return None


def _resolve_node(graph: CallGraph, name: str) -> str:
    """Resolve an entry name (qualified or short) to a node key."""
    if name in graph.nodes:
        return name
    for qname in graph.nodes:
        if qname == name or qname.endswith("." + name) or qname.split(".")[-1] == name:
            return qname
    return name


def reachable_from(callgraph: CallGraph, entry_point: str) -> Set[str]:
    """Return the set of function qualified names reachable from ``entry_point``."""
    start = _resolve_node(callgraph, entry_point)
    seen: Set[str] = set()
    stack: List[str] = [start]
    while stack:
        node = stack.pop()
        if node in seen or node not in callgraph.nodes:
            continue
        seen.add(node)
        for callee in callgraph.edges.get(node, []):
            if callee not in seen:
                stack.append(callee)
    return seen


def find_paths_to_sink(
    callgraph: CallGraph,
    sink_name: str,
    max_depth: int = 10,
) -> List[List[str]]:
    """Find all simple paths from any function to the function named ``sink_name``.

    Cycles are cut with a per-path visited set; paths longer than ``max_depth``
    are abandoned.  Returns call-ordered paths ``[caller, ..., sink]``.
    """
    targets = {
        q for q in callgraph.nodes
        if q == sink_name or q.split(".")[-1] == sink_name
    }
    results: List[List[str]] = []

    def dfs(node: str, path: List[str], visited: Set[str]) -> None:
        if len(path) > max_depth:
            return
        if node in targets and len(path) > 1:
            results.append(list(path))
            return
        for callee in callgraph.edges.get(node, []):
            if callee in visited:
                continue
            visited.add(callee)
            path.append(callee)
            dfs(callee, path, visited)
            path.pop()
            visited.remove(callee)

    for start in callgraph.nodes:
        dfs(start, [start], {start})
    return results


def entry_points(callgraph: CallGraph) -> List[str]:
    """Identify entry points: router-decorated functions or uncalled public functions."""
    called: Set[str] = set()
    for callees in callgraph.edges.values():
        called.update(callees)

    routers: List[str] = []
    for qname, fn in callgraph.nodes.items():
        is_router = any(
            any(hint in dec for hint in _ROUTER_HINTS) for dec in fn.decorators
        )
        is_uncalled_public = qname not in called and not fn.name.startswith("_")
        if is_router or is_uncalled_public:
            routers.append(qname)
    return sorted(routers)
