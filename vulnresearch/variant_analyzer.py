"""Variant analysis and vulnerability-family clustering (PHASE 8).

Once a finding has a confirmed root cause, the same design defect is almost
always repeated elsewhere in the codebase.  This module hunts *variants* of a
finding along five dimensions and then clusters every finding into a
:class:`VulnerabilityFamily` – a shareable "this team keeps making the same
mistake" statement.

Search dimensions (all static, no execution / no network):

1. **same dangerous function** – functions that call the same sink the seed
   finding uses (e.g. every ``subprocess.run(...)``).
2. **same error pattern** – code that matches the root-cause regex.
3. **same missing security boundary** – other functions lacking the same
   sanitiser / authorisation check.
4. **same data flow** – ``source → sink`` pairs of the same shape.
5. **same component** – sibling findings in the same file / module.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .ir import FunctionIR, ProjectIR
from .knowledge_base import category_title
from .models import (
    DataFlowStep,
    EvidenceInfo,
    SinkInfo,
    Vulnerability,
)
from .root_cause import RootCause, RootCauseAnalyzer


# ---------------------------------------------------------------------------
# sink.type -> call-name fragments (mirrors knowledge_base.SINKS)
# ---------------------------------------------------------------------------

_SINK_TYPE_TOKENS: Dict[str, Set[str]] = {
    "sql": {"execute", "executemany", "raw", "query"},
    "command": {"os.system", "os.popen", "subprocess.run", "subprocess.call",
                "subprocess.Popen", "check_output", "popen"},
    "filesystem": {"open", "read_text", "read_bytes", "send_file",
                   "send_from_directory", "write_text", "write_bytes"},
    "network": {"requests.get", "requests.post", "requests.put",
                "requests.delete", "requests.request", "urlopen", "Request"},
    "browser": {"Markup", "mark_safe", "format_html", "redirect"},
    "template": {"render_template_string", "Template", "from_string"},
    "serialization": {"pickle.load", "pickle.loads", "marshal.loads",
                      "yaml.load", "loads"},
    "crypto": {"md5", "sha1", "DES", "MODE_ECB"},
    "nosql": {"find_one", "find", "insert_one", "insert_many",
              "update_one", "delete_one"},
    "authentication": {"login", "authenticate", "verify_token"},
    "authorization": {"admin", "role", "permission"},
    "configuration": {"app.run", "debug", "run("},
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class VulnerabilityFamily:
    """A cluster of findings sharing one root cause.

    Attributes:
        family_id: stable identifier, e.g. ``FAM-001-missing_input_validation``.
        root_cause: the systemic defect shared by every member.
        variants: the findings that belong to this family (deduped).
        shared_component: the file / module most members live in.
        affected_entrypoints: the entry points (function names) implicated.
    """

    family_id: str
    root_cause: RootCause
    variants: List[Vulnerability] = field(default_factory=list)
    shared_component: str = ""
    affected_entrypoints: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class VariantAnalyzer:
    """Hunt variants of a finding and cluster findings into families."""

    def __init__(self, root_cause_analyzer: Optional[RootCauseAnalyzer] = None) -> None:
        self.rc = root_cause_analyzer or RootCauseAnalyzer()

    # ------------------------------------------------------------------
    # variant search
    # ------------------------------------------------------------------

    def find_variants(
        self,
        vuln: Vulnerability,
        project_ir: ProjectIR,
        all_vulns: List[Vulnerability],
    ) -> List[Vulnerability]:
        """Return all variants of *vuln* across the project.

        The seed finding itself is never returned.  Results are deduplicated on
        ``(category, file, line)``.
        """
        rc = self.rc.analyze(vuln)
        tokens = self._sink_tokens(vuln)
        rx = self._compile(self.rc.root_cause_to_pattern(rc))

        seen: Set[tuple] = {(vuln.category, vuln.file, vuln.line)}
        variants: List[Vulnerability] = []

        # dimensions 2-5: correlate with findings already on record
        for other in all_vulns:
            key = (other.category, other.file, other.line)
            if other is vuln or key in seen:
                continue
            if self._matches(vuln, other, tokens, rx):
                variants.append(other)
                seen.add(key)

        # dimension 1: scan the IR for functions invoking the same dangerous
        # call.  Functions that have a real source AND already host a finding
        # are covered above; functions that call the sink but were missed by
        # detectors are synthesised into lightweight variant findings.
        for fn in project_ir.functions:
            if not self._calls_token(fn, tokens):
                continue
            already = any(
                v.file == fn.path and fn.line <= v.line <= fn.end_line
                for v in variants
            )
            if already:
                continue
            if not fn.sources:
                continue  # only surface reachable sinks as variants
            syn = self._synthesize(vuln, fn)
            key = (syn.category, syn.file, syn.line)
            if key not in seen:
                variants.append(syn)
                seen.add(key)

        return variants

    # ------------------------------------------------------------------
    # families / clustering
    # ------------------------------------------------------------------

    def cluster_by_root_cause(
        self, vulns: List[Vulnerability]
    ) -> Dict[str, List[Vulnerability]]:
        """Group *vulns* by inferred root-cause category."""
        groups: Dict[str, List[Vulnerability]] = {}
        for vuln in vulns:
            rc = self.rc.analyze(vuln)
            groups.setdefault(rc.category, []).append(vuln)
        return groups

    def build_families(
        self,
        vulns: List[Vulnerability],
        project_ir: ProjectIR,
    ) -> List[VulnerabilityFamily]:
        """Cluster findings into :class:`VulnerabilityFamily` objects."""
        families: List[VulnerabilityFamily] = []
        groups = self.cluster_by_root_cause(vulns)
        for idx, (rc_category, members) in enumerate(
            sorted(groups.items()), start=1
        ):
            deduped = self._dedup(members)
            root_cause = self.rc.analyze(deduped[0])
            files = [m.file for m in deduped if m.file]
            shared = Counter(files).most_common(1)[0][0] if files else ""
            entrypoints = sorted({
                m.function or f"{m.file}:{m.line}" for m in deduped
            })
            families.append(VulnerabilityFamily(
                family_id=f"FAM-{idx:03d}-{rc_category}",
                root_cause=root_cause,
                variants=deduped,
                shared_component=shared,
                affected_entrypoints=entrypoints,
            ))
        return families

    # ------------------------------------------------------------------
    # matching internals
    # ------------------------------------------------------------------

    def _matches(
        self,
        seed: Vulnerability,
        other: Vulnerability,
        tokens: Set[str],
        rx: Optional[re.Pattern],
    ) -> bool:
        # dimension 1: same dangerous sink function
        if seed.sink.type and other.sink.type and seed.sink.type == other.sink.type:
            return True
        if tokens and any(tok in (other.snippet or "") for tok in tokens):
            return True
        # dimension 2: same error pattern
        if rx is not None and (
            rx.search(other.snippet or "") or rx.search(other.sink.type or "")
        ):
            return True
        # dimension 3: same missing security boundary
        if seed.sanitizer.present == "NO" and other.sanitizer.present == "NO":
            return True
        if seed.authorization.status == "MISSING" \
                and other.authorization.status == "MISSING":
            return True
        # dimension 4: same source -> sink shape
        if (
            seed.source.type
            and other.source.type
            and seed.source.type != "UNKNOWN"
            and seed.source.type == other.source.type
            and seed.sink.type
            and other.sink.type
            and seed.sink.type == other.sink.type
        ):
            return True
        # dimension 5: same component
        if seed.file and other.file and seed.file == other.file:
            return True
        return False

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

    # ------------------------------------------------------------------
    # IR helpers
    # ------------------------------------------------------------------

    def _sink_tokens(self, vuln: Vulnerability) -> Set[str]:
        tokens = set(_SINK_TYPE_TOKENS.get((vuln.sink.type or "").lower(), set()))
        # also pick up longer identifiers mentioned in the snippet as a
        # fallback – short / generic tokens (``py``, ``app`` ...) are dropped
        # to avoid cross-family false positives.
        _GENERIC = {"self", "true", "false", "none", "text", "data", "code",
                    "path", "file", "name", "value"}
        for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_.]{3,}", vuln.snippet or ""):
            leaf = ident.split(".")[-1]
            if len(leaf) >= 4 and leaf.lower() not in _GENERIC:
                tokens.add(leaf)
        return tokens

    @staticmethod
    def _calls_token(fn: FunctionIR, tokens: Set[str]) -> bool:
        if not tokens:
            return False
        for cs in fn.calls:
            for tok in tokens:
                if tok and (tok in cs.name or cs.name.endswith("." + tok)):
                    return True
        return False

    @staticmethod
    def _compile(pattern: str) -> Optional[re.Pattern]:
        if not pattern:
            return None
        try:
            return re.compile(pattern, re.IGNORECASE)
        except re.error:
            return None

    @staticmethod
    def _synthesize(seed: Vulnerability, fn: FunctionIR) -> Vulnerability:
        """Build a lightweight variant finding for a missed dangerous call."""
        line = fn.line
        snippet = fn.calls[0].name if fn.calls else fn.name
        vid = f"VAR-{abs(hash((seed.category, fn.path, fn.name))) % 100000:05d}"
        return Vulnerability(
            id=vid,
            title=category_title(seed.category),
            category=seed.category,
            severity=seed.severity,
            status="potential",
            confidence="Low",
            file=fn.path,
            line=line,
            function=fn.name,
            snippet=snippet,
            sink=SinkInfo(type=seed.sink.type, location=f"{fn.path}:{line}"),
            data_flow=[
                DataFlowStep(step="variant", location=f"{fn.path}:{line}",
                             transformation="same dangerous sink as "
                                            f"{seed.id}")
            ],
            evidence=EvidenceInfo(
                level="E1",
                proof=f"variant: function '{fn.name}' invokes the same "
                      f"dangerous sink family as {seed.id}",
            ),
            remediation=seed.remediation,
        )
