"""Severity rating engine (PHASE 23).

Combines qualitative dimensions into a single Critical / High / Medium / Low /
Info rating, inspired by the CVSS-style scoring model:

* **Impact** – confidentiality / integrity / availability, each 0–3
* **Exploitability** – how easy the flaw is to weaponise, 0–3
* **Privilege Required** – 0–3 (3 = no privileges needed)
* **User Interaction** – 0–1
* **Reachability** – 0–3
* **Scope** – 0–1 (1 = affects components outside the vulnerable trust zone)

Score bands::

    >= 14  Critical
    10-13  High
     6- 9  Medium
     3- 5  Low
     < 3   Info
"""
from __future__ import annotations

from typing import Dict

from .knowledge_base import VULN_CATEGORIES, default_severity
from .models import Vulnerability

# Impact string -> points (0..3)
_IMPACT_POINTS: Dict[str, int] = {
    "CRITICAL": 3,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

_CONFIDENCE_RANK = {"High": 3, "Medium": 2, "Low": 1}


class ImpactScorer:
    """Infer a default (confidentiality, integrity, availability) triplet.

    The default impact is derived from ``knowledge_base.VULN_CATEGORIES`` via
    ``default_severity(category)`` so that e.g. command-injection defaults to a
    much heavier impact than an open-redirect.
    """

    _DEFAULT_IMPACT: Dict[str, Dict[str, str]] = {
        "Critical": {"confidentiality": "CRITICAL", "integrity": "CRITICAL",
                     "availability": "HIGH"},
        "High": {"confidentiality": "HIGH", "integrity": "HIGH",
                 "availability": "MEDIUM"},
        "Medium": {"confidentiality": "MEDIUM", "integrity": "MEDIUM",
                   "availability": "LOW"},
        "Low": {"confidentiality": "LOW", "integrity": "LOW",
                "availability": "UNKNOWN"},
        "Info": {"confidentiality": "UNKNOWN", "integrity": "UNKNOWN",
                 "availability": "UNKNOWN"},
    }

    def __init__(self, category: str):
        self.category = category

    def default_impact(self) -> Dict[str, str]:
        """Return the default C/I/A triplet for the vulnerability category."""
        sev = default_severity(self.category)
        return dict(self._DEFAULT_IMPACT.get(sev, self._DEFAULT_IMPACT["Medium"]))

    def applies_to(self, vuln: Vulnerability) -> None:
        """Materialise the inferred impact onto an empty impact block."""
        inferred = self.default_impact()
        if vuln.impact.confidentiality == "UNKNOWN":
            vuln.impact.confidentiality = inferred["confidentiality"]
        if vuln.impact.integrity == "UNKNOWN":
            vuln.impact.integrity = inferred["integrity"]
        if vuln.impact.availability == "UNKNOWN":
            vuln.impact.availability = inferred["availability"]


class SeverityEngine:
    """Composite severity scoring engine."""

    def rate(self, vuln: Vulnerability, force: bool = False) -> str:
        """Return the Critical/High/Medium/Low/Info rating for *vuln*.

        When *vuln.severity* already carries a concrete rating it is kept
        unless ``force=True`` requests a fresh recomputation.
        """
        existing = (vuln.severity or "").strip()
        if existing and existing not in {"Unknown", "UNKNOWN"} and not force:
            return existing

        # Infer a default impact triplet when nothing was populated yet.
        ImpactScorer(vuln.category).applies_to(vuln)

        score = self._impact(vuln) + self._exploitability(vuln) \
            + self._privilege_required(vuln) + self._user_interaction(vuln) \
            + self._reachability(vuln) + self._scope(vuln)

        rating = self._band(score)
        vuln.severity = rating
        return rating

    # -- dimension scorers --------------------------------------------------

    @staticmethod
    def _impact(vuln: Vulnerability) -> int:
        return (
            _IMPACT_POINTS.get(vuln.impact.confidentiality.upper(), 0)
            + _IMPACT_POINTS.get(vuln.impact.integrity.upper(), 0)
            + _IMPACT_POINTS.get(vuln.impact.availability.upper(), 0)
        )

    @staticmethod
    def _exploitability(vuln: Vulnerability) -> int:
        # Proven, reachable data flow -> easy to exploit.
        if vuln.reachability.status == "REACHABLE" and vuln.data_flow:
            return 3
        if vuln.data_flow:
            return 2
        if vuln.sink.type:
            return 1
        return 0

    @staticmethod
    def _privilege_required(vuln: Vulnerability) -> int:
        # 3 == no privileges required to trigger the flaw.
        if vuln.authentication.required == "NO" and \
                vuln.authorization.required == "NO":
            return 3
        if vuln.authentication.required == "NO" or \
                vuln.authorization.required == "NO":
            return 2
        if vuln.authentication.required == "UNKNOWN" and \
                vuln.authorization.required == "UNKNOWN":
            return 1
        return 0

    @staticmethod
    def _user_interaction(vuln: Vulnerability) -> int:
        # Categories that by design require a victim to click / paste something.
        needs_interaction = {"xss", "open-redirect", "csrf", "phishing",
                             "clickjacking"}
        return 1 if vuln.category in needs_interaction else 0

    @staticmethod
    def _reachability(vuln: Vulnerability) -> int:
        return {"REACHABLE": 3, "UNKNOWN": 1}.get(vuln.reachability.status, 0)

    @staticmethod
    def _scope(vuln: Vulnerability) -> int:
        # Native-memory / supply-chain issues typically cross trust boundaries.
        group = VULN_CATEGORIES.get(vuln.category, {}).get("group", "")
        return 1 if group in {"native-memory", "supply-chain"} else 0

    @staticmethod
    def _band(score: int) -> str:
        if score >= 14:
            return "Critical"
        if score >= 10:
            return "High"
        if score >= 6:
            return "Medium"
        if score >= 3:
            return "Low"
        return "Info"
