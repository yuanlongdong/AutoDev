"""Markdown vulnerability report generator (PHASE 27).

Renders a fully structured, human-readable security research report from a list
of :class:`~vulnresearch.models.Vulnerability` objects.  The report is split
into the fifteen canonical PHASE 27 sections and always distinguishes the
Confirmed / Likely / Potential / Rejected confidence buckets.

Pure Python standard library; no target code is executed and no network I/O
is performed.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .knowledge_base import category_title
from .models import Vulnerability


# Canonical ordering used for severity / confidence tables.
SEVERITY_ORDER: List[str] = ["Critical", "High", "Medium", "Low", "Info"]
CONFIDENCE_ORDER: List[str] = ["High", "Medium", "Low"]
EVIDENCE_LEVELS: List[str] = ["E0", "E1", "E2", "E3", "E4", "E5"]
STATUS_BUCKETS: List[str] = ["confirmed", "likely", "potential", "rejected"]

# Section titles, in order.  Tests assert on these exact strings.
SECTION_TITLES: List[str] = [
    "Summary",
    "Severity",
    "Confidence",
    "Affected Component",
    "Root Cause",
    "Source",
    "Data Flow",
    "Authorization Analysis",
    "Sink",
    "Security Impact",
    "Safe Reproduction",
    "Evidence",
    "Vulnerability Variants",
    "Recommended Fix",
    "Regression Test",
]


def _md_table(headers: List[str], rows: List[List[str]]) -> List[str]:
    """Render a minimal GitHub-flavoured Markdown table."""
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        cells = [str(c).replace("\n", " ").replace("|", "\\|") for c in row]
        out.append("| " + " | ".join(cells) + " |")
    return out


def _status_label(status: str) -> str:
    s = (status or "potential").lower()
    mapping = {
        "confirmed": "Confirmed",
        "likely": "Likely",
        "potential": "Potential",
        "rejected": "Rejected",
    }
    return mapping.get(s, s.capitalize() or "Potential")


class ReportGenerator:
    """Build the fifteen-section PHASE 27 Markdown report."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        vulns: List[Vulnerability],
        project_model: Any = None,
        attack_surface: Any = None,
        families: Optional[Dict[str, List[str]]] = None,
        chains: Optional[List[Any]] = None,
    ) -> str:
        """Render the complete Markdown report.

        Parameters
        ----------
        vulns:
            Vulnerabilities to report on.
        project_model:
            Optional :class:`~vulnresearch.project_model.ProjectModel`.
        attack_surface:
            Optional :class:`~vulnresearch.asset_analyzer.AttackSurface`.
        families:
            Optional mapping ``family_name -> [category, ...]``.
        chains:
            Optional list of vulnerability-chain objects (best-effort rendering).
        """
        vulns = list(vulns or [])
        sections: List[str] = []

        sections.append(self._render_header(project_model, len(vulns)))
        sections.append(self._section_summary(vulns, project_model, attack_surface))
        sections.append(self._section_severity(vulns))
        sections.append(self._section_confidence(vulns))
        sections.append(self._section_affected_component(vulns))
        sections.append(self._section_root_cause(vulns))
        sections.append(self._section_source(vulns))
        sections.append(self._section_data_flow(vulns))
        sections.append(self._section_authorization(vulns))
        sections.append(self._section_sink(vulns))
        sections.append(self._section_security_impact(vulns))
        sections.append(self._section_safe_reproduction(vulns))
        sections.append(self._section_evidence(vulns))
        sections.append(self._section_variants(vulns, families))
        sections.append(self._section_recommended_fix(vulns))
        sections.append(self._section_regression_test(vulns))

        if chains:
            sections.append(self._render_chains(chains))

        return "\n\n".join(s for s in sections if s).rstrip() + "\n"

    def generate_single(self, vuln: Vulnerability) -> str:
        """Render a detailed per-vulnerability Markdown report."""
        lines: List[str] = []
        lines.append(f"# {vuln.title} (`{vuln.id}`)")
        lines.append("")
        lines.extend(_md_table(
            ["Field", "Value"],
            [
                ["Category", vuln.category],
                ["Severity", vuln.severity],
                ["Status", _status_label(vuln.status)],
                ["Confidence", vuln.confidence],
                ["Location", f"{vuln.file}:{vuln.line}"],
                ["Function", vuln.function or "UNKNOWN"],
                ["Sink", vuln.sink.type or "UNKNOWN"],
                ["Reachability", vuln.reachability.status or "UNKNOWN"],
            ],
        ))
        lines.append("")
        lines.append("## Code Snippet")
        lines.append("")
        lines.append("```python")
        lines.append(vuln.snippet or "<no snippet captured>")
        lines.append("```")
        lines.append("")
        lines.append("## Data Flow")
        lines.append("")
        if vuln.data_flow:
            chain = " → ".join(
                step.transformation or step.step or step.location
                for step in vuln.data_flow
            )
            lines.append(f"- Source: `{vuln.source.type}`")
            lines.append(f"- Chain: {chain}")
            lines.append(f"- Sink: `{vuln.sink.type}`")
        else:
            lines.append("- No proven data-flow chain recorded.")
        lines.append("")
        lines.append("## Evidence")
        lines.append("")
        lines.append(f"- Level: **{vuln.evidence.level}**")
        lines.append(f"- Proof: {vuln.evidence.proof or 'n/a'}")
        lines.append("")
        lines.append("## Recommended Fix")
        lines.append("")
        lines.append(vuln.remediation or "No remediation advice available.")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    @staticmethod
    def _render_header(project_model: Any, total: int) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            "# AI Vulnerability Researcher – Security Report",
            "",
            f"_Generated: {now}_  ",
            f"_Total findings: {total}_",
        ]
        if project_model is not None:
            lines.append(
                f"_Project: {getattr(project_model, 'language', 'unknown')} / "
                f"{', '.join(getattr(project_model, 'frameworks', []) or ['no framework'])}_"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 1. Summary
    # ------------------------------------------------------------------

    def _section_summary(
        self, vulns: List[Vulnerability], project_model: Any, attack_surface: Any
    ) -> str:
        lines = ["## 1. Summary", ""]
        lines.append(f"**Total vulnerabilities:** {len(vulns)}")
        lines.append("")
        sev_counts = Counter(v.severity for v in vulns)
        status_counts = Counter((v.status or "potential").lower() for v in vulns)
        lines.append("By status:")
        for bucket in STATUS_BUCKETS:
            lines.append(f"- {_status_label(bucket)}: {status_counts.get(bucket, 0)}")
        lines.append("")
        lines.append("By severity:")
        for sev in SEVERITY_ORDER:
            lines.append(f"- {sev}: {sev_counts.get(sev, 0)}")
        lines.append("")
        if project_model is not None:
            lines.append("**Project overview:**")
            lines.append(f"- Language: {getattr(project_model, 'language', 'unknown')}")
            fw = getattr(project_model, "frameworks", []) or []
            lines.append(f"- Frameworks: {', '.join(fw) or 'none detected'}")
            dbs = getattr(project_model, "databases", []) or []
            lines.append(f"- Datastores: {', '.join(dbs) or 'none detected'}")
            lines.append(f"- Authentication: {getattr(project_model, 'authentication', 'unknown')}")
            lines.append(f"- Authorization: {getattr(project_model, 'authorization', 'unknown')}")
        if attack_surface is not None:
            assets = getattr(attack_surface, "assets", []) or []
            lines.append(f"- Attack-surface assets enumerated: {len(assets)}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 2. Severity
    # ------------------------------------------------------------------

    def _section_severity(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 2. Severity", ""]
        counts = Counter(v.severity for v in vulns)
        rows = [[sev, str(counts.get(sev, 0))] for sev in SEVERITY_ORDER]
        lines.extend(_md_table(["Severity", "Count"], rows))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 3. Confidence
    # ------------------------------------------------------------------

    def _section_confidence(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 3. Confidence", ""]
        conf = Counter(v.confidence for v in vulns)
        lines.append("### Confidence distribution")
        lines.append("")
        lines.extend(_md_table(
            ["Confidence", "Count"],
            [[c, str(conf.get(c, 0))] for c in CONFIDENCE_ORDER],
        ))
        lines.append("")
        ev = Counter((v.evidence.level or "E1") for v in vulns)
        lines.append("### Evidence level distribution (E0–E5)")
        lines.append("")
        lines.extend(_md_table(
            ["Evidence Level", "Count"],
            [[lvl, str(ev.get(lvl, 0))] for lvl in EVIDENCE_LEVELS],
        ))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 4. Affected Component
    # ------------------------------------------------------------------

    def _section_affected_component(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 4. Affected Component", ""]
        if not vulns:
            lines.append("No affected components.")
            return "\n".join(lines)
        rows = []
        for v in vulns:
            component = v.function or v.file or v.sink.location or "unknown"
            rows.append([v.id, v.title, v.file or "-", str(v.line), component])
        lines.extend(_md_table(
            ["ID", "Title", "File", "Line", "Function / Component"], rows
        ))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 5. Root Cause
    # ------------------------------------------------------------------

    def _section_root_cause(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 5. Root Cause", ""]
        clusters: Dict[str, List[Vulnerability]] = defaultdict(list)
        for v in vulns:
            key = v.root_cause or v.category or "unspecified"
            clusters[key].append(v)
        if not clusters:
            lines.append("No root-cause clusters identified.")
            return "\n".join(lines)
        rows = []
        for cause, items in sorted(clusters.items(), key=lambda kv: -len(kv[1])):
            cats = sorted({i.category for i in items})
            rows.append([cause, str(len(items)), ", ".join(cats)])
        lines.extend(_md_table(["Root Cause", "Count", "Categories"], rows))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 6. Source
    # ------------------------------------------------------------------

    def _section_source(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 6. Source", ""]
        counts = Counter((v.source.type or "UNKNOWN") for v in vulns)
        if not counts:
            lines.append("No attacker-controllable sources identified.")
            return "\n".join(lines)
        rows = [[src, str(n)] for src, n in counts.most_common()]
        lines.extend(_md_table(["Source Type", "Count"], rows))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 7. Data Flow
    # ------------------------------------------------------------------

    def _section_data_flow(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 7. Data Flow", ""]
        if not vulns:
            lines.append("No data-flow paths recorded.")
            return "\n".join(lines)
        for v in vulns:
            lines.append(f"### {v.id} — {v.title}")
            lines.append("")
            source = v.source.type or "UNKNOWN"
            sink = v.sink.type or "UNKNOWN"
            if v.data_flow:
                hops = [f"SOURCE({source})"]
                for step in v.data_flow:
                    label = step.transformation or step.step or step.location
                    hops.append(label)
                hops.append(f"SINK({sink})")
                lines.append("`" + " → ".join(hops) + "`")
            else:
                lines.append(f"`SOURCE({source}) → ? → SINK({sink})` "
                             "_(no proven intermediate hops)_")
            lines.append("")
        return "\n".join(lines).rstrip()

    # ------------------------------------------------------------------
    # 8. Authorization Analysis
    # ------------------------------------------------------------------

    def _section_authorization(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 8. Authorization Analysis", ""]
        rows = []
        for v in vulns:
            auth_note = ""
            if v.authentication.required != "UNKNOWN" and v.authorization.required == "UNKNOWN":
                auth_note = "authenticated but authorization unverified"
            if v.category == "idor" or v.category == "bola":
                auth_note = (auth_note + "; " if auth_note else "") + "potential IDOR/BOLA"
            rows.append([
                v.id,
                v.category,
                v.authentication.required,
                v.authorization.required,
                auth_note or "-",
            ])
        if not rows:
            lines.append("No authentication/authorization findings.")
        else:
            lines.extend(_md_table(
                ["ID", "Category", "Auth Required", "AuthZ Required", "Note"], rows
            ))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 9. Sink
    # ------------------------------------------------------------------

    def _section_sink(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 9. Sink", ""]
        counts = Counter((v.sink.type or "unknown") for v in vulns)
        rows = [[sink, str(n)] for sink, n in counts.most_common()]
        lines.extend(_md_table(["Sink Type", "Count"], rows))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 10. Security Impact
    # ------------------------------------------------------------------

    def _section_security_impact(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 10. Security Impact", ""]
        rows = []
        for v in vulns:
            imp = v.impact
            rows.append([
                v.id,
                v.title,
                imp.confidentiality or "UNKNOWN",
                imp.integrity or "UNKNOWN",
                imp.availability or "UNKNOWN",
                imp.privilege or "UNKNOWN",
            ])
        if not rows:
            lines.append("No impact data available.")
        else:
            lines.extend(_md_table(
                ["ID", "Title", "Confidentiality", "Integrity", "Availability", "Privilege"],
                rows,
            ))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 11. Safe Reproduction
    # ------------------------------------------------------------------

    def _section_safe_reproduction(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 11. Safe Reproduction", ""]
        lines.append("All reproduction is **non-destructive and static-first**:")
        lines.append("")
        lines.append("- Static proof: taint analysis shows source → sink reachability.")
        lines.append("- Unit-test evidence: existing regression tests, if any.")
        lines.append("- No live attack payloads are executed and no network calls are made.")
        lines.append("")
        rows = []
        for v in vulns:
            method = v.verification.method or "static analysis"
            env = v.verification.environment or "static"
            result = v.verification.result or (
                "confirmed" if v.data_flow and v.reachability.status == "REACHABLE"
                else "pending review"
            )
            rows.append([v.id, env, method, result])
        if rows:
            lines.extend(_md_table(["ID", "Environment", "Method", "Result"], rows))
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 12. Evidence
    # ------------------------------------------------------------------

    def _section_evidence(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 12. Evidence", ""]
        for v in vulns:
            lines.append(f"- **{v.id}** ({v.evidence.level}): {v.evidence.proof or 'n/a'}")
        if not vulns:
            lines.append("No evidence recorded.")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # 13. Vulnerability Variants
    # ------------------------------------------------------------------

    def _section_variants(self, vulns: List[Vulnerability],
                          families: Optional[Dict[str, List[str]]]) -> str:
        lines = ["## 13. Vulnerability Variants", ""]
        if families:
            for family, members in sorted(families.items()):
                lines.append(f"### Family: {family}")
                for member in members:
                    lines.append(f"- {member}")
                lines.append("")
        else:
            families_seen: Dict[str, List[str]] = defaultdict(list)
            for v in vulns:
                fam = v.vulnerability_family or v.category
                families_seen[fam].append(v.title or category_title(v.category))
            if not families_seen:
                lines.append("No vulnerability families identified.")
            for fam, titles in sorted(families_seen.items()):
                lines.append(f"### Family: {fam}")
                for t in sorted(set(titles)):
                    lines.append(f"- {t}")
                lines.append("")
        return "\n".join(lines).rstrip()

    # ------------------------------------------------------------------
    # 14. Recommended Fix
    # ------------------------------------------------------------------

    def _section_recommended_fix(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 14. Recommended Fix", ""]
        for v in vulns:
            lines.append(f"### {v.id} — {v.title}")
            lines.append("")
            lines.append(v.remediation or "No remediation advice available.")
            lines.append("")
        if not vulns:
            lines.append("No remediation needed.")
        return "\n".join(lines).rstrip()

    # ------------------------------------------------------------------
    # 15. Regression Test
    # ------------------------------------------------------------------

    def _section_regression_test(self, vulns: List[Vulnerability]) -> str:
        lines = ["## 15. Regression Test", ""]
        for v in vulns:
            test_name = self._test_name(v)
            lines.append(f"### {v.id} — {test_name}")
            lines.append("")
            lines.append("```python")
            lines.append(self._test_body(v))
            lines.append("```")
            lines.append("")
        if not vulns:
            lines.append("No regression test scenarios.")
        return "\n".join(lines).rstrip()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _test_name(v: Vulnerability) -> str:
        base = (v.category or "vulnerability").replace("-", "_")
        loc = (v.file or "").replace("/", "_").replace(".", "_")
        return f"test_regression_{base}_{v.line}"

    def _test_body(self, v: Vulnerability) -> str:
        return (
            f"def {self._test_name(v)}():\n"
            f"    # Regression for {v.id}: {v.title}\n"
            f"    # Location: {v.file}:{v.line}\n"
            f"    input_value = {{attacker_controlled_input}}\n"
            f"    result = target_handler(input_value)\n"
            f"    assert not is_dangerous(result), "
            f"'{v.category} regression triggered'\n"
        )

    @staticmethod
    def _render_chains(chains: List[Any]) -> str:
        lines = ["## Appendix. Vulnerability Chains", ""]
        for i, chain in enumerate(chains, 1):
            lines.append(f"### Chain {i}")
            lines.append("")
            if isinstance(chain, dict):
                for key, val in chain.items():
                    lines.append(f"- {key}: {val}")
            else:
                lines.append(f"- {chain}")
            lines.append("")
        return "\n".join(lines).rstrip()
