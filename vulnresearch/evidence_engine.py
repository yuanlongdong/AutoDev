"""Evidence level auto-evaluation engine (PHASE 14).

Maps the structured fields of a :class:`~vulnresearch.models.Vulnerability`
object onto the E0–E5 evidence ladder:

======= ==================================================================
Level   Meaning
======= ==================================================================
E0      Speculation only – no sink was even located
E1      Suspicious code located (sink present, no source / data flow)
E2      Source → Data Flow → Sink proven
E3      Reachability + Controllability + Security boundary failure
E4      Security reproduction (successful verification)
E5      Impact confirmed (high/critical confidentiality or integrity)
======= ==================================================================

The engine never executes target code and never performs network I/O; it only
reads declarative fields already populated by earlier analysis passes.
"""
from __future__ import annotations

from typing import Dict, Tuple

from .models import Vulnerability

# ---------------------------------------------------------------------------
# Level bookkeeping
# ---------------------------------------------------------------------------

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
    """Return the human-readable description for an E0–E5 level string."""
    return EVIDENCE_LABELS.get(level, f"{level}: unknown evidence level")


def _rank(level: str) -> int:
    return _LEVEL_RANK.get(level, 1)


class EvidenceEngine:
    """Automatic E0–E5 evidence-level evaluator."""

    # -- core API ----------------------------------------------------------

    def evaluate(self, vuln: Vulnerability) -> Vulnerability:
        """Recompute the evidence level from the vulnerability's fields.

        Applies the upgrade/downgrade decision and records the reason on the
        vulnerability itself.  Returns the same object for chaining.
        """
        target, reason = self._compute_target(vuln)
        current = vuln.evidence.level or "E1"

        if _rank(target) > _rank(current):
            self.upgrade(vuln, target, reason)
        elif _rank(target) < _rank(current):
            self.downgrade(vuln, target, reason)
        return vuln

    def upgrade(self, vuln: Vulnerability, target_level: str, reason: str) -> None:
        """Raise the evidence level and append *reason* to the proof log."""
        vuln.evidence.level = target_level
        self._record(vuln, f"[upgrade → {target_level}] {reason}")

    def downgrade(self, vuln: Vulnerability, target_level: str, reason: str) -> None:
        """Lower the evidence level and append *reason* to the proof log."""
        vuln.evidence.level = target_level
        self._record(vuln, f"[downgrade → {target_level}] {reason}")

    # -- internal rules ----------------------------------------------------

    def _compute_target(self, vuln: Vulnerability) -> Tuple[str, str]:
        sink_present = bool(vuln.sink.type)

        # E0 – nothing but speculation: no sink at all.
        if vuln.source.type == "UNKNOWN" and not sink_present:
            return "E0", "No sink located; assessment is pure speculation"

        # Default starting point: suspicious sink located.
        level = "E1"
        reason = "Suspicious sink located; no proven source/data flow yet"

        # E2 – the full data-flow chain is proven.
        if (
            vuln.source.type != "UNKNOWN"
            and vuln.data_flow
            and sink_present
        ):
            level = "E2"
            reason = (
                f"Source '{vuln.source.type}' → {len(vuln.data_flow)}-hop data flow "
                f"→ sink '{vuln.sink.type}' proven"
            )

        # E3 – reachable, uncontrolled, and crosses a security boundary.
        if (
            vuln.reachability.status == "REACHABLE"
            and vuln.sanitizer.present == "NO"
            and (
                vuln.authorization.status == "MISSING"
                or vuln.authentication.status == "MISSING"
            )
        ):
            auth_gap = (
                "authorization missing"
                if vuln.authorization.status == "MISSING"
                else "authentication missing"
            )
            level = "E3"
            reason = (
                "Reachable from attacker input, no sanitizer, and "
                f"{auth_gap} – security boundary failure proven"
            )

        # E4 – a successful reproduction / verification.
        result_lower = (vuln.verification.result or "").lower()
        if (
            bool(vuln.verification.method)
            and ("success" in result_lower or "confirmed" in result_lower)
        ):
            level = "E4"
            reason = (
                f"Security reproduction successful via "
                f"'{vuln.verification.method}': {vuln.verification.result}"
            )

        # E5 – concrete real-world impact, requires E4 minimum.
        if _rank(level) >= _rank("E4") and self._has_high_impact(vuln):
            level = "E5"
            reason = (
                "Impact confirmed: confidentiality/integrity reaches "
                "HIGH or CRITICAL"
            )

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
