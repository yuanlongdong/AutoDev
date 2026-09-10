"""Taint propagation analysis: SOURCE -> TRANSFORM -> SANITIZER -> SINK.

The engine tracks attacker-controllable values from their source, propagates
them through assignments (intra-procedurally, precisely) and reports every
flow that reaches a sink.  If the propagated value passes through a known
sanitizer the flow is flagged ``sanitized=True`` so the evidence engine can
downgrade the finding.

Cross-function propagation is deliberately conservative: only direct
parameter passing along call-graph edges is modelled (no alias analysis).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set

from .ir import FunctionIR, ProjectIR
from .models import DataFlowStep
from .knowledge_base import SOURCE_TOKENS, SANITIZER_FUNCTIONS
from .dataflow import DataFlowAnalyzer, DataFlowResult
from .callgraph import CallGraph

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass
class TaintFlow:
    """One complete SOURCE -> ... -> SINK path."""

    source: str
    path: List[DataFlowStep] = field(default_factory=list)
    sink: str = ""
    sanitized: bool = False


def build_data_flow_steps(taint_flow: TaintFlow) -> List[DataFlowStep]:
    """Convert a :class:`TaintFlow` into a list of :class:`DataFlowStep`."""
    return list(taint_flow.path)


class TaintEngine:
    """Taint tracker for one or many functions."""

    def __init__(self) -> None:
        self.analyzer = DataFlowAnalyzer()
        self._file_cache: Dict[str, List[str]] = {}

    # ------------------------------------------------------------------
    # intra-procedural analysis
    # ------------------------------------------------------------------

    def analyze_function(
        self,
        function_ir: FunctionIR,
        dataflow_result: DataFlowResult,
        source_lines: List[str],
        seed_vars: Set[str] | None = None,
    ) -> List[TaintFlow]:
        tainted = self._tainted_vars(function_ir, dataflow_result, seed_vars)
        sanitized = self._sanitized_vars(function_ir, dataflow_result, tainted)

        flows: List[TaintFlow] = []
        for cs in function_ir.calls:
            if not self._is_sink(cs.name, function_ir):
                continue
            used_args = [a for a in cs.args if any(v in a for v in tainted)]
            if not used_args:
                continue
            reached = {v for arg in used_args for v in tainted if v in arg}
            steps = self._build_steps(function_ir, dataflow_result, cs, tainted, sanitized)
            flows.append(TaintFlow(
                source=self._origin(function_ir, dataflow_result),
                path=steps,
                sink=cs.name,
                sanitized=any(v in sanitized for v in reached),
            ))
        return flows

    # ------------------------------------------------------------------
    # cross-function analysis
    # ------------------------------------------------------------------

    def analyze_project(self, project_ir: ProjectIR, callgraph: CallGraph) -> List[TaintFlow]:
        # cache data-flow results for every function in the project
        df_map: Dict[str, tuple] = {}
        for fn in project_ir.functions:
            lines = self._read_lines(fn.path)
            df_map[fn.qualified_name] = (fn, self.analyzer.analyze(fn, lines))

        flows: List[TaintFlow] = []
        # 1) intra-procedural flows
        for qn, (fn, df) in df_map.items():
            flows.extend(self.analyze_function(fn, df, self._read_lines(fn.path)))

        # 2) conservative cross-function parameter propagation
        for caller_qn, callees in callgraph.edges.items():
            caller_pair = df_map.get(caller_qn)
            if caller_pair is None:
                continue
            caller_fn, caller_df = caller_pair
            caller_tainted = self._tainted_vars(caller_fn, caller_df)
            for cs in caller_fn.calls:
                callee_qn = self._resolve_callee(callgraph, cs.name)
                if callee_qn not in df_map:
                    continue
                tainted_args = [a for a in cs.args if any(v in a for v in caller_tainted)]
                if not tainted_args:
                    continue
                callee_fn, callee_df = df_map[callee_qn]
                # seed the callee's positional parameters with taint
                seeded = set(callee_fn.parameters[: len(cs.args)])
                if not seeded:
                    continue
                cross_flows = self.analyze_function(
                    callee_fn, callee_df, self._read_lines(callee_fn.path),
                    seed_vars=seeded,
                )
                for fl in cross_flows:
                    if caller_fn.sources:
                        fl.source = caller_fn.sources[0]
                flows.extend(cross_flows)
        return flows

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    @staticmethod
    def _tainted_vars(
        fn: FunctionIR,
        df: DataFlowResult,
        seed_vars: Set[str] | None = None,
    ) -> Set[str]:
        tainted: Set[str] = set(seed_vars or ())

        def refs(expr: str) -> Set[str]:
            return set(_IDENT_RE.findall(expr))

        changed = True
        while changed:
            changed = False
            for d in df.definitions:
                if d.var_name in tainted:
                    continue
                rhs = d.expression
                if any(tok and tok in rhs for tok in SOURCE_TOKENS):
                    tainted.add(d.var_name)
                    changed = True
                elif refs(rhs) & tainted:
                    tainted.add(d.var_name)
                    changed = True
        return tainted

    @staticmethod
    def _sanitized_vars(
        fn: FunctionIR,
        df: DataFlowResult,
        tainted: Set[str],
    ) -> Set[str]:
        sanitized: Set[str] = set()
        for cs in fn.calls:
            if not any(san in cs.name for san in SANITIZER_FUNCTIONS):
                continue
            touched = [a for a in cs.args if any(v in a for v in tainted)]
            if not touched:
                continue
            for d in df.definitions:
                if cs.name in d.expression:
                    sanitized.add(d.var_name)
        return sanitized

    @staticmethod
    def _is_sink(name: str, fn: FunctionIR) -> bool:
        if name in fn.sinks:
            return True
        return any(name.startswith(s + ".") for s in fn.sinks)

    @staticmethod
    def _origin(fn: FunctionIR, df: DataFlowResult) -> str:
        if fn.sources:
            return fn.sources[0]
        for d in df.definitions:
            if any(tok and tok in d.expression for tok in SOURCE_TOKENS):
                return d.expression
        return "unknown"

    @staticmethod
    def _build_steps(
        fn: FunctionIR,
        df: DataFlowResult,
        sink_call,
        tainted: Set[str],
        sanitized: Set[str],
    ) -> List[DataFlowStep]:
        steps: List[DataFlowStep] = [
            DataFlowStep(step="source", location=f"{fn.path}:{fn.line}",
                         transformation=TaintEngine._origin(fn, df)),
        ]
        for d in df.definitions:
            if d.var_name in tainted:
                tag = "transform(sanitized)" if d.var_name in sanitized else "transform"
                steps.append(DataFlowStep(
                    step=tag,
                    location=f"{fn.path}:{d.line}",
                    transformation=f"{d.var_name} = {d.expression}",
                ))
        steps.append(DataFlowStep(
            step="sink",
            location=f"{fn.path}:{sink_call.line}",
            transformation=sink_call.name,
        ))
        return steps

    @staticmethod
    def _resolve_callee(callgraph: CallGraph, call_name: str):
        if not call_name or call_name == "<dynamic>":
            return None
        if call_name in callgraph.nodes:
            return call_name
        short = call_name.split(".")[-1]
        for qn in callgraph.nodes:
            if qn.split(".")[-1] == short:
                return qn
        return None

    def _read_lines(self, path: str) -> List[str]:
        if path not in self._file_cache:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    self._file_cache[path] = fh.read().splitlines()
            except OSError:
                self._file_cache[path] = []
        return self._file_cache[path]
