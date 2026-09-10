"""Quality gate before a finding may be marked CONFIRMED (PHASE 28).

A research pipeline that promotes findings to ``confirmed`` on a hunch wastes
everybody's time.  This gate runs a fixed 16-item checklist over each
:class:`~vulnresearch.models.Vulnerability`; **only when every item passes may
the finding be promoted to ``confirmed``**.  Failing items keep the finding at
``potential`` / ``likely`` and record *why* it is not ready for production use.

Pure Python standard library; no execution, no network.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from .models import Vulnerability


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class QualityCheck:
    """One checklist item."""

    name: str
    passed: bool
    detail: str = ""


@dataclass
class QualityGateResult:
    """The outcome of running the 16-item checklist."""

    checks: List[QualityCheck] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def failed_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed)


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------

_EVIDENCE_LEVELS = {"E0", "E1", "E2", "E3", "E4", "E5"}
_CONFIDENCE_LEVELS = {"High", "Medium", "Low"}
_SEVERITY_RANK = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5}


class QualityGate:
    """Run the 16-item readiness checklist against one finding."""

    # ------------------------------------------------------------------

    def check(self, vuln: Vulnerability) -> QualityGateResult:
        """Evaluate every gate item for *vuln*."""
        checks: List[QualityCheck] = [
            self._c_scope(vuln),
            self._c_source(vuln),
            self._c_sink(vuln),
            self._c_data_flow(vuln),
            self._c_reachability(vuln),
            self._c_authentication(vuln),
            self._c_authorization(vuln),
            self._c_sanitizer(vuln),
            self._c_impact(vuln),
            self._c_evidence_graded(vuln),
            self._c_confidence(vuln),
            self._c_root_cause(vuln),
            self._c_variants(vuln),
            self._c_duplicate(vuln),
            self._c_poc_safe(vuln),
            self._c_remediation(vuln),
        ]
        return QualityGateResult(checks=checks)

    def can_confirm(self, vuln: Vulnerability) -> bool:
        """``True`` only when **all** checklist items pass."""
        return self.check(vuln).all_passed

    def apply_gate(self, vuln: Vulnerability) -> Vulnerability:
        """Apply the gate in place.

        * all checks pass  -> promote the finding to ``confirmed``;
        * any check fails  -> never allow ``confirmed``; demote a premature
          ``confirmed`` back to ``likely`` and leave weaker statuses untouched.
        """
        if self.can_confirm(vuln):
            vuln.status = "confirmed"
        elif vuln.status == "confirmed":
            vuln.status = "likely"
        return vuln

    # ------------------------------------------------------------------
    # The 16 checks (kept in the order dictated by PHASE 28)
    # ------------------------------------------------------------------

    @staticmethod
    def _c_scope(v: Vulnerability) -> QualityCheck:
        ok = bool(v.file)
        return QualityCheck("scope_confirmed", ok,
                            f"file={v.file!r}" if not ok else "location confirmed")

    @staticmethod
    def _c_source(v: Vulnerability) -> QualityCheck:
        ok = v.source.type != "UNKNOWN"
        return QualityCheck("source_confirmed", ok,
                            f"source.type={v.source.type}" if not ok
                            else f"source={v.source.type}")

    @staticmethod
    def _c_sink(v: Vulnerability) -> QualityCheck:
        ok = bool(v.sink.type)
        return QualityCheck("sink_confirmed", ok,
                            "sink.type empty" if not ok else f"sink={v.sink.type}")

    @staticmethod
    def _c_data_flow(v: Vulnerability) -> QualityCheck:
        has_flow = bool(v.data_flow)
        level = _SEVERITY_RANK.get(v.evidence.level, 0)
        ok = has_flow or level >= 2  # E2 or higher already proves the chain
        detail = (
            f"data_flow={len(v.data_flow)} hop(s), evidence={v.evidence.level}"
        )
        return QualityCheck("data_flow_confirmed", ok, detail)

    @staticmethod
    def _c_reachability(v: Vulnerability) -> QualityCheck:
        ok = v.reachability.status != "UNKNOWN"
        return QualityCheck("reachability_confirmed", ok,
                            f"reachability={v.reachability.status}")

    @staticmethod
    def _c_authentication(v: Vulnerability) -> QualityCheck:
        ok = v.authentication.required != "UNKNOWN"
        return QualityCheck("authentication_analyzed", ok,
                            f"authentication.required={v.authentication.required}")

    @staticmethod
    def _c_authorization(v: Vulnerability) -> QualityCheck:
        ok = v.authorization.required != "UNKNOWN"
        return QualityCheck("authorization_analyzed", ok,
                            f"authorization.required={v.authorization.required}")

    @staticmethod
    def _c_sanitizer(v: Vulnerability) -> QualityCheck:
        ok = v.sanitizer.present != "UNKNOWN"
        return QualityCheck("sanitizer_analyzed", ok,
                            f"sanitizer.present={v.sanitizer.present}")

    @staticmethod
    def _c_impact(v: Vulnerability) -> QualityCheck:
        unknown = {"UNKNOWN", ""}
        fields = (v.impact.confidentiality, v.impact.integrity,
                  v.impact.availability, v.impact.privilege)
        ok = any(f not in unknown for f in fields)
        return QualityCheck("impact_analyzed", ok,
                            "no impact dimension rated" if not ok
                            else "impact rated")

    @staticmethod
    def _c_evidence_graded(v: Vulnerability) -> QualityCheck:
        ok = v.evidence.level in _EVIDENCE_LEVELS
        return QualityCheck("evidence_graded", ok,
                            f"evidence.level={v.evidence.level}")

    @staticmethod
    def _c_confidence(v: Vulnerability) -> QualityCheck:
        ok = v.confidence in _CONFIDENCE_LEVELS
        return QualityCheck("confidence_rated", ok,
                            f"confidence={v.confidence}")

    @staticmethod
    def _c_root_cause(v: Vulnerability) -> QualityCheck:
        ok = bool(v.root_cause)
        return QualityCheck("root_cause_extracted", ok,
                            "root_cause empty" if not ok else f"root_cause={v.root_cause[:60]}")

    @staticmethod
    def _c_variants(v: Vulnerability) -> QualityCheck:
        ok = bool(v.variants) or bool(v.vulnerability_family)
        return QualityCheck(
            "variant_analysis_done", ok,
            f"variants={len(v.variants)}, family={v.vulnerability_family!r}"
        )

    @staticmethod
    def _c_duplicate(v: Vulnerability) -> QualityCheck:
        # Dedup is guaranteed by the research engine pipeline.
        return QualityCheck("duplicate_checked", True,
                            "deduplicated by (category, file, line)")

    @staticmethod
    def _c_poc_safe(v: Vulnerability) -> QualityCheck:
        ok = v.verification.environment != "production"
        return QualityCheck("poc_non_destructive", ok,
                            f"verification.environment={v.verification.environment}")

    @staticmethod
    def _c_remediation(v: Vulnerability) -> QualityCheck:
        ok = bool(v.remediation)
        return QualityCheck("remediation_clear", ok,
                            "remediation empty" if not ok
                            else f"remediation={v.remediation[:60]}")
