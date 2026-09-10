"""Automatic downgrade rule engine (PHASE 19).

A research pipeline that only ever *escalates* findings quickly drowns the
analyst in noise.  This pass looks for reasons a candidate vulnerability might
**not** be exploitable and, when several fire at once, lowers confidence,
trims the evidence level and relaxes the status of the finding.

Rules are pure predicates over the ``Vulnerability`` object plus a free-form
``context`` dict produced by reachability / build-system passes.
"""
from __future__ import annotations

from typing import Dict, List

from .models import Vulnerability

_CONFIDENCE_DOWN = {"High": "Medium", "Medium": "Low", "Low": "Low"}

# Evidence ladder bookkeeping (mirrors evidence_engine._LEVEL_RANK).
_RANK = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5}
_RANK_TO_LEVEL = {v: k for k, v in _RANK.items()}

_MAX_EVIDENCE_DROP = 2


class DowngradeEngine:
    """Evaluate and apply automatic downgrade rules."""

    # -- detection ----------------------------------------------------------

    def check(self, vuln: Vulnerability, context: Dict) -> List[str]:
        """Return the list of human-readable reasons that fired."""
        reasons: List[str] = []
        path = vuln.file or ""

        if vuln.sanitizer.present == "UNKNOWN":
            reasons.append(
                "Unknown sanitizer: whether input is encoded/validated cannot be determined"
            )
        if vuln.authorization.required == "UNKNOWN":
            reasons.append(
                "Unknown authorization: whether an access-control check exists is unknown"
            )
        if vuln.reachability.status == "UNKNOWN":
            reasons.append(
                "Unknown reachability: the tainted path has not been confirmed reachable"
            )
        if context.get("dead_code"):
            reasons.append(
                "Dead code: the containing function is never reachable in the build graph"
            )
        if vuln.reachability.status == "UNREACHABLE":
            reasons.append(
                "Unreachable branch: the tainted statement lives on a dead branch"
            )
        if context.get("feature_enabled") is False:
            reasons.append(
                "Feature disabled: the flagged code path is behind an off-by-default feature flag"
            )
        if context.get("dependency_reachable") is False:
            reasons.append(
                "Dependency not reachable: the vulnerable dependency is never imported"
            )
        if context.get("false_positive_pattern"):
            reasons.append(
                "False-positive pattern: the code matches a known scanner false-positive idiom"
            )
        if self._is_test_only_path(path):
            reasons.append(
                "Test-only code: the file belongs to the test suite, not production code"
            )
        return reasons

    @staticmethod
    def _is_test_only_path(path: str) -> bool:
        norm = path.replace("\\", "/")
        return (
            "test_" in norm
            or "/tests/" in norm
            or norm.endswith("/tests")
            or norm.startswith("tests/")
            or "conftest" in norm
        )

    # -- application --------------------------------------------------------

    def apply(self, vuln: Vulnerability, context: Dict) -> Vulnerability:
        """Apply every triggered rule to *vuln* in place and return it.

        * Confidence moves one rung down the High → Medium → Low ladder.
        * Evidence level drops by one per trigger, capped at two levels.
        * A previously ``confirmed`` finding is demoted to ``potential``.
        """
        reasons = self.check(vuln, context)
        if not reasons:
            return vuln

        vuln.confidence = _CONFIDENCE_DOWN.get(vuln.confidence, vuln.confidence)

        drop = min(_MAX_EVIDENCE_DROP, len(reasons))
        current = _RANK.get(vuln.evidence.level, 1)
        new_rank = max(0, current - drop)
        vuln.evidence.level = _RANK_TO_LEVEL[new_rank]

        if vuln.status == "confirmed":
            vuln.status = "potential"

        log = "\n".join(f"[downgrade] {r}" for r in reasons)
        if vuln.evidence.proof:
            vuln.evidence.proof = f"{vuln.evidence.proof}\n{log}"
        else:
            vuln.evidence.proof = log
        return vuln
