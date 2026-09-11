"""Cross-function call-graph construction and reachability analysis.

The graph is deliberately conservative: ambiguous short-name calls are not
resolved unless the caller's class/module context provides a unique candidate.
This prevents unrelated same-named functions from being connected merely by
string coincidence.
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
                target = self._resolve(cs.name, fn, nodes, by_short_name)
                if target and target not in seen:
                    seen.add(target)
                    callees.append(target)
            edges[fn.qualified_name] = callees
        return CallGraph(nodes=nodes, edges=edges)

    @staticmethod
    def _resolve(
        call_name: str,
        caller: FunctionIR,
        nodes: Dict[str, FunctionIR],
        by_short_name: Dict[str, List[str]],
    ) -> str | None:
        """Resolve a call conservatively, returning ``None`` when ambiguous."""
        if not call_name or call_name == "<dynamic>":
            return None
        if call_name in nodes:
            return call_name

        short = call_name.split(".")[-1]
        candidates = by_short_name.get(short, [])
        if not candidates:
            return None
        if len(candidates) == 1:
            return candidates[0]

        # ``self.method()`` / ``cls.method()``: prefer the caller's class.
        if call_name.startswith(("self.", "cls.")) and caller.class_name:
            scoped = [c for c in candidates if c == f"{caller.class_name}.{short}"]
            if len(scoped) == 1:
                return scoped[0]

        # A dotted module/function call can be matched against the qualified
        # suffix only when that suffix identifies exactly one candidate.
        suffix = "." + call_name
        scoped = [c for c in candidates if c.endswith(suffix)]
        if len(scoped) == 1:
            return scoped[0]

        # Do not guess. An unresolved edge is safer than a false program
        # relationship in vulnerability-chain analysis.
        return None


def _resolve_node(graph: CallGraph, name: str) -> str:
    """Resolve an entry name (qualified or short) to a node key."""
    if name in graph.nodes:
        return name
    matches = [
        qname for qname in graph.nodes
        if qname.endswith("." + name) or qname.split(".")[-1] == name
    ]
    return matches[0] if len(matches) == 1 else name


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
    """Find simple call paths from any function to ``sink_name``."""
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
    """Identify router-decorated or otherwise uncalled public functions."""
    called: Set[str] = set()
    for callees in callgraph.edges.values():
        called.update(callees)

    routers: List[str] = []
    for qname, fn in callgraph.nodes.items():
        is_router = any(any(hint in dec for hint in _ROUTER_HINTS) for dec in fn.decorators)
        is_uncalled_public = qname not in called and not fn.name.startswith("_")
        if is_router or is_uncalled_public:
            routers.append(qname)
    return sorted(routers)
