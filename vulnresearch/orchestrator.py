"""Automated research-loop orchestrator (PHASE 24).

Ties every earlier engine together into one end-to-end research loop:

1. build IR + call graph + project model + attack surface
2. run the structured :class:`~vulnresearch.detectors.DetectorPipeline`
3. enrich each finding with :class:`~vulnresearch.taint_engine.TaintEngine`
   data-flow (upgrade evidence E1 -> E2)
4. run :class:`~vulnresearch.counter_evidence.CounterEvidenceEngine`
5. run :class:`~vulnresearch.downgrade.DowngradeEngine`
6. re-grade evidence with :class:`~vulnresearch.evidence_engine.EvidenceEngine`
7. rate severity with :class:`~vulnresearch.severity.SeverityEngine`
8. extract root causes with :class:`~vulnresearch.root_cause.RootCauseAnalyzer`
9. hunt variants / build families with
   :class:`~vulnresearch.variant_analyzer.VariantAnalyzer`
10. discover chains with :class:`~vulnresearch.chain_analyzer.ChainAnalyzer`
11. apply the :class:`~vulnresearch.quality_gate.QualityGate`
12. deduplicate on ``(category, file, line)``

Variant search iterates up to :pyattr:`max_iterations` times, stopping early
when no new High / Medium variant is found.  The whole loop is purely static:
it never executes the analysed code and never performs network I/O.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set

from .asset_analyzer import AssetAnalyzer, AttackSurface
from .callgraph import CallGraph, CallGraphBuilder
from .chain_analyzer import ChainAnalyzer, VulnerabilityChain
from .counter_evidence import CounterEvidenceEngine
from .dataflow import DataFlowAnalyzer
from .detectors import DetectorPipeline, scan_file
from .downgrade import DowngradeEngine
from .evidence_engine import EvidenceEngine
from .ir import FunctionIR, ProjectIR, extract_python
from .models import DataFlowStep, SourceInfo, Vulnerability
from .project_model import ProjectModel, ProjectModeler
from .quality_gate import QualityGate
from .root_cause import RootCause, RootCauseAnalyzer
from .severity import SeverityEngine
from .taint_engine import TaintEngine, build_data_flow_steps
from .variant_analyzer import VariantAnalyzer, VulnerabilityFamily


_EXCLUDES = {".git", ".hg", ".venv", "venv", "env", "node_modules",
             "dist", "build", "__pycache__", ".tox", ".mypy_cache",
             ".pytest_cache"}


class Orchestrator:
    """Drive the full automated research loop over a source tree."""

    #: variant search stops after this many rounds with no new finding
    max_iterations: int = 3

    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()
        self._file_lines: Dict[str, List[str]] = {}

        # step 1 – structural model
        self.project_ir: ProjectIR = self._build_ir()
        self.callgraph: CallGraph = CallGraphBuilder().build(self.project_ir)
        self.project_model: ProjectModel = ProjectModeler().build(
            str(self.root), self.project_ir
        )
        self.attack_surface: AttackSurface = AssetAnalyzer().analyze(
            self.project_ir, self.project_model
        )

        # analysis engines (constructed once, reused)
        self._taint = TaintEngine()
        self._dataflow = DataFlowAnalyzer()
        self._evidence = EvidenceEngine()
        self._severity = SeverityEngine()
        self._counter = CounterEvidenceEngine()
        self._downgrader = DowngradeEngine()
        self._root_cause = RootCauseAnalyzer()
        self._variants = VariantAnalyzer(self._root_cause)
        self._chains = ChainAnalyzer()
        self._gate = QualityGate()

    # ------------------------------------------------------------------
    # structural build
    # ------------------------------------------------------------------

    def _build_ir(self) -> ProjectIR:
        functions: List[FunctionIR] = []
        imports: List[str] = []
        classes: List[dict] = []
        for py in sorted(self.root.rglob("*.py")):
            if any(part in _EXCLUDES for part in py.parts):
                continue
            ir = extract_python(py)
            functions.extend(ir.functions)
            imports.extend(ir.imports)
            classes.extend(ir.classes)
        return ProjectIR(functions=functions, imports=imports, classes=classes)

    def _lines(self, path: str) -> List[str]:
        if path not in self._file_lines:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    self._file_lines[path] = fh.read().splitlines()
            except OSError:
                self._file_lines[path] = []
        return self._file_lines[path]

    # ------------------------------------------------------------------
    # detection (steps 2)
    # ------------------------------------------------------------------

    def _detect(self) -> List[Vulnerability]:
        pipeline = DetectorPipeline()
        vulns: List[Vulnerability] = []

        # legacy regex scan
        for py in sorted(self.root.rglob("*.py")):
            if any(part in _EXCLUDES for part in py.parts):
                continue
            try:
                for finding in scan_file(py):
                    vulns.append(finding.to_vulnerability())
            except Exception:
                continue

        # structured detectors per function
        by_path: Dict[str, List[FunctionIR]] = {}
        for fn in self.project_ir.functions:
            by_path.setdefault(fn.path, []).append(fn)
        for path, fns in by_path.items():
            lines = self._lines(path)
            for fn in fns:
                try:
                    vulns.extend(pipeline.run(fn, lines, self.project_ir))
                except Exception:
                    continue
        return self._dedup(vulns)

    # ------------------------------------------------------------------
    # taint enrichment (step 3)
    # ------------------------------------------------------------------

    def _find_function(self, v: Vulnerability) -> Optional[FunctionIR]:
        if v.function:
            for fn in self.project_ir.functions:
                if fn.path == v.file and fn.name == v.function:
                    return fn
        for fn in self.project_ir.functions:
            if fn.path == v.file and fn.line <= v.line <= fn.end_line:
                return fn
        return None

    @staticmethod
    def _normalize_source(token: str) -> str:
        t = (token or "").lower()
        if not t or t == "unknown":
            return "UNKNOWN"
        if "request.args" in t or "query" in t:
            return "http_query"
        if "request.files" in t or "multipart" in t:
            return "http_multipart"
        if "request.json" in t:
            return "http_json"
        if "request.data" in t or "request.body" in t or "request.form" in t:
            return "http_body"
        if "request" in t:
            return "http"
        if "environ" in t or "getenv" in t:
            return "env_var"
        return t

    def _enrich_with_taint(self, vulns: List[Vulnerability]) -> None:
        for v in vulns:
            fn = self._find_function(v)
            if fn is None:
                continue
            lines = self._lines(fn.path)
            try:
                df = self._dataflow.analyze(fn, lines)
                flows = self._taint.analyze_function(fn, df, lines)
            except Exception:
                continue
            if not flows:
                continue
            flow = flows[0]
            if v.source.type == "UNKNOWN":
                v.source = SourceInfo(
                    type=self._normalize_source(flow.source),
                    description=flow.source,
                )
            v.data_flow = build_data_flow_steps(flow)
            v.sanitizer.present = "YES" if flow.sanitized else "NO"
            self._evidence.evaluate(v)

    # ------------------------------------------------------------------
    # counter-evidence payload (step 4)
    # ------------------------------------------------------------------

    def _ir_data(self, v: Vulnerability) -> dict:
        funcs = []
        for fn in self.project_ir.functions:
            if fn.path != v.file:
                continue
            funcs.append({
                "name": fn.name,
                "calls": [{"name": c.name} for c in fn.calls],
            })
        return {
            "source_text": "\n".join(self._lines(v.file)),
            "context": {},
            "functions": funcs,
        }

    # ------------------------------------------------------------------
    # variant loop (step 9)
    # ------------------------------------------------------------------

    @staticmethod
    def _key(v: Vulnerability) -> tuple:
        return (v.category, v.file, v.line)

    @staticmethod
    def _dedup(vulns: List[Vulnerability]) -> List[Vulnerability]:
        seen: Set[tuple] = set()
        out: List[Vulnerability] = []
        for v in vulns:
            key = (v.category, v.file, v.line)
            if key in seen:
                continue
            seen.add(key)
            out.append(v)
        return out

    def _is_new_high_value(self, cand: Vulnerability,
                           existing: List[Vulnerability]) -> bool:
        if any(self._key(cand) == self._key(e) for e in existing):
            return False
        return cand.severity in {"High", "Critical", "Medium"}

    # ------------------------------------------------------------------
    # main loop
    # ------------------------------------------------------------------

    def run(self) -> dict:
        """Execute the complete research loop and return the results bundle."""
        # step 2 – initial detection
        vulns: List[Vulnerability] = self._detect()

        # step 3 – taint enrichment
        self._enrich_with_taint(vulns)

        # step 4 – counter evidence (may trim evidence / mark sanitizers)
        for v in vulns:
            try:
                self._counter.apply_counter_evidence(v, self._ir_data(v))
            except Exception:
                pass

        # step 5 – automatic downgrade
        for v in vulns:
            try:
                self._downgrader.apply(v, {})
            except Exception:
                pass

        # step 6 – re-grade evidence
        for v in vulns:
            self._evidence.evaluate(v)

        # step 7 – severity rating
        for v in vulns:
            try:
                self._severity.rate(v, force=True)
            except Exception:
                pass

        # findings whose evidence collapsed to E0 are rejected outright
        for v in vulns:
            if v.evidence.level == "E0":
                v.status = "rejected"

        # step 8 – root causes (batch list now; per-vuln assignment happens
        # after the variant loop so freshly discovered variants also get one)
        root_causes: List[RootCause] = self._root_cause.analyze_batch(vulns)

        # step 9 – variant search (iterative until no new high-value variant)
        iterations = 0
        for iterations in range(1, self.max_iterations + 1):
            added_this_round = 0
            for v in list(vulns):
                variants = self._variants.find_variants(
                    v, self.project_ir, vulns
                )
                v.variants = [f"{x.file}:{x.line}" for x in variants]
                for nv in variants:
                    if self._is_new_high_value(nv, vulns):
                        vulns.append(nv)
                        added_this_round += 1
            if added_this_round == 0:
                break

        # attach root-cause descriptions to every finding (incl. variants)
        for v in vulns:
            v.root_cause = self._root_cause.analyze(v).description
        root_causes = self._root_cause.analyze_batch(vulns)

        families: List[VulnerabilityFamily] = self._variants.build_families(
            vulns, self.project_ir
        )
        for fam in families:
            for member in fam.variants:
                member.vulnerability_family = fam.family_id

        # step 10 – chains
        chains: List[VulnerabilityChain] = self._chains.find_chains(
            vulns, self.callgraph
        )

        # step 11 – quality gate
        for v in vulns:
            self._gate.apply_gate(v)

        # step 12 – dedup
        vulns = self._dedup(vulns)

        rejected = [v for v in vulns if v.status == "rejected"]
        survivors = [v for v in vulns if v.status != "rejected"]

        stats = {
            "total": len(vulns),
            "iterations": iterations,
            "by_status": dict(Counter(v.status for v in vulns)),
            "by_severity": dict(Counter(v.severity for v in vulns)),
            "by_root_cause": dict(Counter(v.root_cause for v in vulns)),
            "families": len(families),
            "chains": len(chains),
            "rejected": len(rejected),
            "attack_surface_assets": len(self.attack_surface.assets),
        }

        return {
            "vulnerabilities": survivors,
            "root_causes": root_causes,
            "families": families,
            "chains": chains,
            "attack_surface": self.attack_surface,
            "rejected": rejected,
            "stats": stats,
        }
