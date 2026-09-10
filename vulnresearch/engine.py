"""Research engine orchestration (PHASE 27 integration).

Wires the regex fallback scanner together with the structured detector
pipeline, the evidence engine, counter-evidence pass, automatic downgrade
rules and the severity scorer into a single :class:`ResearchEngine`.

Backward compatibility is guaranteed:

* ``ResearchEngine.run()`` still returns ``List[Finding]``;
* ``DEFAULT_EXCLUDES`` / ``DEFAULT_EXTS`` are unchanged;
* the analysed code is never executed and no network I/O occurs.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .detectors import DetectorPipeline, scan_file, scan_file_with_ir
from .ir import ProjectIR, extract_file
from .models import Finding, Vulnerability

DEFAULT_EXCLUDES = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__",
                    # v0.5.1: skip test trees.  Test helpers / fixtures issue outbound
                    # HTTP calls (e.g. ``requests.post(GRAPHQL_URL, ...)``) that are
                    # not application SSRF sinks.  Our own ``tests/fixtures/`` are read
                    # directly by the unit tests via ``scan_file_with_ir`` and never
                    # walked through ``ResearchEngine.files()``.
                    "tests", "test", "__tests__",
                    # v0.6.0: exploit / proof-of-concept scripts hammer the target
                    # (``requests.post(TARGET, ...)``) from an attacker machine; they
                    # are never application code and produce pure SSRF noise.
                    "exploits"}
DEFAULT_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".php", ".rb", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs"}

# v0.5.1: filenames that are always test scaffolding regardless of directory.
# We deliberately match only ``conftest.py`` here, not ``test_*.py`` /
# ``*_test.py``: the regression baseline (``sast-target``) ships a top-level
# POC script named ``test_vulnerabilities.py`` whose findings are part of the
# "48 findings" floor, and blanket-excluding ``test_*.py`` would silently drop
# that floor.  Test-code noise that matters in practice (graphql-target's 17
# SSRF false positives) lives inside a ``tests/`` directory and is already
# removed by ``DEFAULT_EXCLUDES`` above.
_TEST_FILE_RE = re.compile(r"^conftest\.py$")

# Severity weight used when clustering/selecting the "best" representative.
_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# Normalisation map: legacy regex category → canonical structured category.
# After mapping, findings that hit the same (file, line, snippet) via both
# paths collapse into one (the more precise structured label wins).
_CATEGORY_NORMALIZE: Dict[str, str] = {
    "secret": "hardcoded-secret",
    "deserialization": "insecure-deserialization",
}


def _normalize_categories(vulns: List[Vulnerability]) -> None:
    """Rename legacy category labels in-place to their canonical forms."""
    for v in vulns:
        canonical = _CATEGORY_NORMALIZE.get(v.category)
        if canonical:
            v.category = canonical


def _normalize_finding_categories(findings: List[Finding]) -> None:
    """Rename legacy category labels on legacy Findings (in-place)."""
    for f in findings:
        canonical = _CATEGORY_NORMALIZE.get(f.category)
        if canonical:
            f.category = canonical


def _merge_ir(ir_a: ProjectIR, ir_b: ProjectIR) -> ProjectIR:
    """Merge two :class:`ProjectIR` objects (functions/imports/classes)."""
    return ProjectIR(
        functions=list(ir_a.functions) + list(ir_b.functions),
        imports=list(ir_a.imports) + list(ir_b.imports),
        classes=list(ir_a.classes) + list(ir_b.classes),
    )


class ResearchEngine:
    """Orchestrate regex scanning + deep structured analysis."""

    def __init__(self, root: str, max_files: int = 10000):
        self.root = Path(root).resolve()
        self.max_files = max_files
        # lazily-built artefacts
        self._ir: Optional[ProjectIR] = None
        self._project_model: Optional[Any] = None
        self._attack_surface: Optional[Any] = None

    # ------------------------------------------------------------------
    # File discovery (unchanged)
    # ------------------------------------------------------------------

    def files(self) -> Iterable[Path]:
        # v0.3.1: ``root`` may point at a single file.  ``rglob("*")`` does not
        # yield the file itself, so handle that case explicitly before walking.
        if self.root.is_file():
            if self.root.suffix.lower() in DEFAULT_EXTS:
                yield self.root
            return
        count = 0
        for p in self.root.rglob("*"):
            if count >= self.max_files:
                break
            if not p.is_file() or p.suffix.lower() not in DEFAULT_EXTS:
                continue
            if any(part in DEFAULT_EXCLUDES for part in p.parts):
                continue
            # v0.5.1: skip test-file scaffolding even outside a tests/ tree.
            if p.suffix.lower() == ".py" and _TEST_FILE_RE.match(p.name):
                continue
            count += 1
            yield p

    # ------------------------------------------------------------------
    # IR / project model / attack surface
    # ------------------------------------------------------------------

    def build_ir(self) -> ProjectIR:
        """Build the merged :class:`ProjectIR` for the scanned tree (cached)."""
        if self._ir is not None:
            return self._ir
        ir = ProjectIR()
        for path in self.files():
            if path.suffix.lower() != ".py":
                continue
            try:
                ir = _merge_ir(ir, extract_file(path))
            except Exception:
                continue
        self._ir = ir
        return ir

    def build_project_model(self, project_ir: Optional[ProjectIR] = None) -> Any:
        """Build the :class:`ProjectModel` for the tree (cached)."""
        if self._project_model is not None:
            return self._project_model
        from .project_model import ProjectModeler  # local import: stdlib only
        ir = project_ir if project_ir is not None else self.build_ir()
        try:
            self._project_model = ProjectModeler().build(str(self.root), ir)
        except Exception:
            self._project_model = None
        return self._project_model

    def build_attack_surface(self, project_ir: Optional[ProjectIR] = None) -> Any:
        """Build the enumerated :class:`AttackSurface` (cached)."""
        if self._attack_surface is not None:
            return self._attack_surface
        from .asset_analyzer import AssetAnalyzer
        ir = project_ir if project_ir is not None else self.build_ir()
        model = self.build_project_model(ir)
        try:
            self._attack_surface = AssetAnalyzer().analyze(ir, model)
        except Exception:
            from .asset_analyzer import AttackSurface
            self._attack_surface = AttackSurface()
        return self._attack_surface

    # ------------------------------------------------------------------
    # Deep analysis
    # ------------------------------------------------------------------

    def run_vulnerabilities(self) -> List[Vulnerability]:
        """Run the full structured pipeline and return ``Vulnerability`` objects.

        Steps: structured detectors → evidence engine → counter-evidence →
        automatic downgrade → severity rating → root-cause clustering.
        """
        ir = self.build_ir()
        raw: List[Vulnerability] = []

        for path in self.files():
            if path.suffix.lower() != ".py":
                continue
            try:
                raw.extend(scan_file_with_ir(path, ir))
            except Exception:
                continue

        # Normalise legacy category labels so that e.g. ``secret`` (regex)
        # and ``hardcoded-secret`` (structured) merge on the same location.
        _normalize_categories(raw)

        # v0.2.2: dedup by (category, file, line) — not by snippet.  When the
        # same location/category is reported by both the legacy regex scanner
        # and the structured IR detector, keep the richer (structured) one.
        # Different categories on the same line are kept separate.
        vulns = self._dedup_by_location(raw, key=lambda v: (v.category, v.file, v.line))

        self._refine(vulns)
        return self.deduplicate_by_root_cause(vulns)

    def _refine(self, vulns: List[Vulnerability]) -> None:
        """Apply evidence / counter-evidence / downgrade / severity passes."""
        from .evidence_engine import EvidenceEngine
        from .counter_evidence import CounterEvidenceEngine
        from .downgrade import DowngradeEngine
        from .severity import SeverityEngine

        evidence = EvidenceEngine()
        counter = CounterEvidenceEngine()
        downgrade = DowngradeEngine()
        severity = SeverityEngine()
        ir_data: Dict[str, Any] = {"context": {}}

        for v in vulns:
            try:
                evidence.evaluate(v)
            except Exception:
                pass
            try:
                counter.apply_counter_evidence(v, ir_data)
            except Exception:
                pass
            try:
                downgrade.apply(v, {})
            except Exception:
                pass
            try:
                severity.rate(v)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Deep / combined entry points
    # ------------------------------------------------------------------

    def run_deep(self) -> Dict[str, Any]:
        """Run the whole pipeline and return a structured research result."""
        vulns = self.run_vulnerabilities()
        attack_surface = self.build_attack_surface()
        project_model = self.build_project_model()

        root_causes: Dict[str, List[str]] = defaultdict(list)
        families: Dict[str, List[str]] = defaultdict(list)
        for v in vulns:
            root_causes[v.root_cause or v.category].append(v.id)
            fam = v.vulnerability_family or v.category
            families.setdefault(fam, [])
            if v.category not in families[fam]:
                families[fam].append(v.category)

        status_counts = Counter((v.status or "potential").lower() for v in vulns)
        severity_counts = Counter(v.severity for v in vulns)

        return {
            "vulnerabilities": vulns,
            "root_causes": dict(root_causes),
            "families": dict(families),
            "chains": [],
            "attack_surface": attack_surface,
            "project_model": project_model,
            "stats": {
                "total": len(vulns),
                "by_status": dict(status_counts),
                "by_severity": dict(severity_counts),
            },
        }

    # ------------------------------------------------------------------
    # Legacy backward-compatible entry point
    # ------------------------------------------------------------------

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        # 1. regex fallback scan (the v0.1.x behaviour)
        for path in self.files():
            findings.extend(scan_file(path))
        # 2. merge in structured Vulnerabilities converted back to Findings
        try:
            vulns = self.run_vulnerabilities()
        except Exception:
            vulns = []
        for v in vulns:
            findings.append(v.to_finding())
        # Normalise legacy labels before final dedup so ``secret`` and
        # ``hardcoded-secret`` on the same line collapse.
        _normalize_finding_categories(findings)
        return self.deduplicate(findings)

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    @staticmethod
    def _evidence_proof(obj) -> str:
        """Return the evidence proof for either Finding or Vulnerability."""
        ev = getattr(obj, "evidence", "")
        if isinstance(ev, str):
            return ev or ""                       # legacy Finding
        return getattr(ev, "proof", "") or ""     # Vulnerability (EvidenceInfo)

    @staticmethod
    def _evidence_level(obj) -> str:
        lvl = getattr(obj, "evidence_level", None)
        if lvl is not None:
            return lvl
        return getattr(getattr(obj, "evidence", None), "level", "") or "E0"

    @staticmethod
    def _dataflow_len(obj) -> int:
        df = getattr(obj, "data_flow", None)
        return len(df) if isinstance(df, list) else 0

    @staticmethod
    def _dedup_by_location(items, key):
        """Collapse findings sharing the same ``key`` to one representative.

        The richer finding wins: longer evidence proof, an explicit data
        flow and a higher evidence level are preferred (this keeps the
        structured detector's result over the legacy regex's generic one).
        Original first-seen ordering is preserved.
        """
        level_rank = {"E5": 5, "E4": 4, "E3": 3, "E2": 2, "E1": 1, "E0": 0}
        groups: Dict[tuple, list] = {}
        order: Dict[int, int] = {}
        for i, it in enumerate(items):
            k = key(it)
            groups.setdefault(k, []).append(it)
            order.setdefault(id(it), i)
        result = []
        for members in groups.values():
            best = max(members, key=lambda m: (
                level_rank.get(ResearchEngine._evidence_level(m), 0),
                ResearchEngine._dataflow_len(m),
                len(ResearchEngine._evidence_proof(m)),
            ))
            result.append(best)
        result.sort(key=lambda m: order.get(id(m), 1_000_000))
        return result

    @staticmethod
    def deduplicate(findings: List[Finding]) -> List[Finding]:
        """v0.2.2: dedup by (category, path, line), keeping the best finding.

        Same-location, same-category duplicates produced by the legacy regex
        scanner and the structured IR detector are collapsed; different
        categories on the same line (e.g. path-traversal + file-write) are
        preserved.
        """
        return ResearchEngine._dedup_by_location(
            findings, key=lambda f: (f.category, f.path, f.line),
        )

    @staticmethod
    def deduplicate_by_root_cause(vulns: List[Vulnerability]) -> List[Vulnerability]:
        """Cluster vulnerabilities by root cause and keep one representative.

        Vulnerabilities that share the same non-empty ``root_cause`` are folded
        together; the representative is the highest-severity finding.  Items
        without a root cause are always preserved.
        """
        groups: Dict[str, List[Vulnerability]] = defaultdict(list)
        orphans: List[Vulnerability] = []
        for v in vulns:
            cause = (v.root_cause or "").strip()
            if not cause:
                orphans.append(v)
            else:
                groups[cause].append(v)

        result: List[Vulnerability] = list(orphans)
        for cause, members in groups.items():
            representative = max(
                members,
                key=lambda v: (_SEVERITY_RANK.get(v.severity, 0), v.evidence.level),
            )
            result.append(representative)
        # stable order: preserve original first-seen ordering
        order = {id(v): i for i, v in enumerate(vulns)}
        result.sort(key=lambda v: order.get(id(v), 1_000_000))
        return result
