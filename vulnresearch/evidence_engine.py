"""Evidence level auto-evaluation engine (PHASE 14).

Maps structured vulnerability evidence onto the E0-E5 ladder without executing
or contacting the target. Higher levels are cumulative: a later claim cannot
skip the source/data-flow/reachability evidence required by earlier levels.
"""
from __future__ import annotations

from typing import Dict, Tuple

from .models import Vulnerability

_LEVEL_RANK: Dict[str, int] = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5}

EVIDENCE_LABELS: Dict[str, str] = {
    "E0": "E0: Speculation only – no sink located yet",
    "E1": "E1: Suspicious code located (sink present, no proven source)",
    "E2": "E2: Source → Data Flow → Sink proven",
    "E3": "E3: Reachability, controllability and boundary failure proven",
    "E4": "E4: Security reproduction succeeded",
    "E5": "E5: Real-world impact confirmed",
}


def evidence_label(level: str) -> str:
    return EVIDENCE_LABELS.get(level, f"{level}: unknown evidence level")


def _rank(level: str) -> int:
    return _LEVEL_RANK.get(level, 1)


class EvidenceEngine:
    """Automatically evaluate cumulative E0-E5 evidence."""

    def evaluate(self, vuln: Vulnerability) -> Vulnerability:
        target, reason = self._compute_target(vuln)
        current = vuln.evidence.level or "E1"
        if _rank(target) > _rank(current):
            self.upgrade(vuln, target, reason)
        elif _rank(target) < _rank(current):
            self.downgrade(vuln, target, reason)
        return vuln

    def upgrade(self, vuln: Vulnerability, target_level: str, reason: str) -> None:
        vuln.evidence.level = target_level
        self._record(vuln, f"[upgrade → {target_level}] {reason}")

    def downgrade(self, vuln: Vulnerability, target_level: str, reason: str) -> None:
        vuln.evidence.level = target_level
        self._record(vuln, f"[downgrade → {target_level}] {reason}")

    def _compute_target(self, vuln: Vulnerability) -> Tuple[str, str]:
        sink_present = bool(vuln.sink.type)
        source_present = vuln.source.type != "UNKNOWN"
        flow_proven = bool(vuln.data_flow)

        if not sink_present:
            return "E0", "No sink located; assessment is pure speculation"

        level = "E1"
        reason = "Suspicious sink located; no proven source/data flow yet"

        # E2 is the prerequisite for every higher evidence level.
        if source_present and flow_proven:
            level = "E2"
            reason = (
                f"Source '{vuln.source.type}' → {len(vuln.data_flow)}-hop data flow "
                f"→ sink '{vuln.sink.type}' proven"
            )

        # E3 cannot be reached merely because an endpoint is reachable. It must
        # already have a proven source-to-sink path, plus a missing security
        # boundary and no known sanitizer.
        if (
            level == "E2"
            and vuln.reachability.status == "REACHABLE"
            and vuln.sanitizer.present == "NO"
            and (
                vuln.authorization.status in {"MISSING", "BYPASSED"}
                or vuln.authentication.status in {"MISSING", "BYPASSED"}
            )
        ):
            auth_gap = (
                "authorization missing/bypassed"
                if vuln.authorization.status in {"MISSING", "BYPASSED"}
                else "authentication missing/bypassed"
            )
            level = "E3"
            reason = (
                "Reachable source-to-sink path, no sanitizer, and "
                f"{auth_gap} – security boundary failure proven"
            )

        # E4 still requires a proven source-to-sink path and actual reachability;
        # verification text alone must never manufacture evidence.
        result_lower = (vuln.verification.result or "").lower()
        if (
            level in {"E2", "E3"}
            and vuln.reachability.status == "REACHABLE"
            and bool(vuln.verification.method)
            and ("success" in result_lower or "confirmed" in result_lower)
        ):
            level = "E4"
            reason = (
                f"Security reproduction successful via '{vuln.verification.method}': "
                f"{vuln.verification.result}"
            )

        # E5 requires E4 plus a concrete high/critical confidentiality or
        # integrity impact. This prevents impact labels from bypassing proof.
        if level == "E4" and self._has_high_impact(vuln):
            level = "E5"
            reason = "Impact confirmed: confidentiality/integrity reaches HIGH or CRITICAL"

        return level, reason

    @staticmethod
    def _has_high_impact(vuln: Vulnerability) -> bool:
        high = {"HIGH", "CRITICAL"}
        return vuln.impact.confidentiality in high or vuln.impact.integrity in high

    @staticmethod
    def _record(vuln: Vulnerability, entry: str) -> None:
        if vuln.evidence.proof:
            vuln.evidence.proof = f"{vuln.evidence.proof}\n{entry}"
        else:
            vuln.evidence.proof = entry
