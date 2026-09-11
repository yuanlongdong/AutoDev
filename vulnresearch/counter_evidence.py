"""Counter-evidence engine (PHASE 21).

Counter-evidence must be scoped to the vulnerable path. Project-wide string
matches are intentionally treated as weak assumptions rather than proof.
The module never executes target code and never performs network I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .knowledge_base import AUTH_PATTERNS, SANITIZERS
from .models import Vulnerability

_SANITIZER_TOKENS: List[str] = sorted(
    {name for names in SANITIZERS.values() for name in names if name},
    key=len,
    reverse=True,
)
_ORM_METHOD_HINTS = (".filter", ".filter_by", ".get(", ".query", "select(",
                     ".order_by", ".all()", "session.query", "Model.objects")
_RAW_SQL_HINTS = ("raw", "execute(", "executemany", "RawSQL", "extra(",
                  "text(", "UNION ", "SELECT ")
_RANK = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5}
_RANK_TO_LEVEL = {v: k for k, v in _RANK.items()}


def _hit(found: bool, description: str, evidence_type: str) -> Dict[str, Any]:
    return {"found": found, "description": description, "evidence_type": evidence_type}


def _scope_text(vuln: Vulnerability, ir_data: Dict[str, Any]) -> str:
    """Build the narrowest available evidence scope.

    Prefer the finding snippet/data-flow and the owning function/body when
    supplied. A project-wide source corpus is retained only as an explicit
    fallback and is marked as an assumption by callers.
    """
    parts: List[str] = [vuln.snippet, vuln.sink.type, vuln.sink.location]
    parts.extend(step.step for step in vuln.data_flow)
    parts.extend(step.transformation for step in vuln.data_flow)

    function_name = getattr(vuln, "function", "") or ""
    for func in ir_data.get("functions", []) or []:
        if not isinstance(func, dict):
            continue
        if function_name and str(func.get("name", "")) != function_name:
            continue
        parts.append(str(func.get("name", "")))
        if func.get("body"):
            parts.append(str(func["body"]))
        for call in func.get("calls", []) or []:
            parts.append(str(call.get("name", "")) if isinstance(call, dict) else str(call))
        break
    return "\n".join(p for p in parts if p)


class CounterEvidenceEngine:
    """Look for reasons a candidate vulnerability might not be exploitable."""

    def analyze(self, vuln: Vulnerability, ir_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        scoped = _scope_text(vuln, ir_data)
        context: Dict[str, Any] = ir_data.get("context", {}) or {}
        return {
            "hidden_sanitizer": self._check_hidden_sanitizer(scoped),
            "middleware_auth": self._check_middleware_auth(scoped),
            "unified_authz": self._check_unified_authz(scoped),
            "service_layer_check": self._check_service_layer(ir_data, scoped),
            "unreachable_path": self._check_unreachable_path(vuln),
            "disabled_config": self._check_disabled_config(context),
            "framework_auto_encoding": self._check_framework_auto_encoding(scoped),
            "orm_auto_parameterization": self._check_orm_auto_parameterization(vuln, scoped),
        }

    def _check_hidden_sanitizer(self, corpus: str) -> Dict[str, Any]:
        hits = [t for t in _SANITIZER_TOKENS if t and t in corpus]
        if hits:
            return _hit(True, f"Known sanitizer(s) present in finding scope: {', '.join(hits[:5])}", "evidence")
        return _hit(False, "No known sanitizer found in finding scope", "evidence")

    def _check_middleware_auth(self, corpus: str) -> Dict[str, Any]:
        hits = [d for d in AUTH_PATTERNS["authentication_decorators"] if d in corpus]
        if hits:
            return _hit(True, f"Authentication decorator/middleware observed in finding scope: {', '.join(hits)}", "evidence")
        return _hit(False, "No authentication decorator/middleware found in finding scope", "evidence")

    def _check_unified_authz(self, corpus: str) -> Dict[str, Any]:
        hits = [f for f in AUTH_PATTERNS["authorization_functions"] if f in corpus]
        if hits:
            return _hit(True, f"Authorization check observed in finding scope: {', '.join(hits)}", "evidence")
        return _hit(False, "No authorization check found in finding scope", "evidence")

    def _check_service_layer(self, ir_data: Dict[str, Any], corpus: str) -> Dict[str, Any]:
        funcs = ir_data.get("functions", []) or []
        for func in funcs:
            if not isinstance(func, dict) or "service" not in str(func.get("name", "")).lower():
                continue
            blob = "\n".join(str(c.get("name", "")) if isinstance(c, dict) else str(c)
                               for c in (func.get("calls", []) or []))
            if any(t in blob for t in _SANITIZER_TOKENS) or any(a in blob for a in AUTH_PATTERNS["authorization_functions"]):
                return _hit(True, f"Service-layer function '{func.get('name', '')}' performs an additional check", "assumption")
        return _hit(False, "No path-local service-layer check proven", "assumption")

    @staticmethod
    def _check_unreachable_path(vuln: Vulnerability) -> Dict[str, Any]:
        if vuln.reachability.status == "UNREACHABLE":
            return _hit(True, "Reachability analysis marks the path UNREACHABLE", "evidence")
        return _hit(False, "Tainted path is not marked unreachable", "evidence")

    @staticmethod
    def _check_disabled_config(context: Dict[str, Any]) -> Dict[str, Any]:
        if context.get("feature_enabled") is False or context.get("enabled") is False or context.get("disabled") is True:
            return _hit(True, "Configuration disables the affected feature", "evidence")
        return _hit(False, "Feature appears enabled", "evidence")

    @staticmethod
    def _check_framework_auto_encoding(corpus: str) -> Dict[str, Any]:
        lowered = corpus.lower()
        if "django" in lowered or "from django" in lowered:
            return _hit(True, "Django detected – template auto-escaping is a framework assumption; verify the sink", "assumption")
        if "jinja" in lowered or "flask" in lowered or "render_template" in lowered:
            return _hit(True, "Jinja2/Flask detected – auto-escaping may apply; verify configuration and sink", "assumption")
        return _hit(False, "No framework auto-encoding guarantee detected", "assumption")

    @staticmethod
    def _check_orm_auto_parameterization(vuln: Vulnerability, corpus: str) -> Dict[str, Any]:
        sink_text = f"{vuln.sink.type} {corpus}".lower()
        is_orm = any(h.lower() in sink_text for h in _ORM_METHOD_HINTS)
        is_raw = any(h.lower() in sink_text for h in _RAW_SQL_HINTS)
        if is_orm and not is_raw:
            return _hit(True, "ORM-like sink observed in finding scope; parameterisation still requires verification", "assumption")
        return _hit(False, "Sink is not clearly an auto-parameterised ORM call", "evidence")

    def apply_counter_evidence(self, vuln: Vulnerability, ir_data: Dict[str, Any]) -> Vulnerability:
        report = self.analyze(vuln, ir_data)
        notes: List[str] = []

        if report["hidden_sanitizer"]["found"]:
            vuln.sanitizer.present = "YES"
            vuln.sanitizer.description = report["hidden_sanitizer"]["description"]
            notes.append("path-local sanitizer observed")
        if report["orm_auto_parameterization"]["found"] and report["orm_auto_parameterization"]["evidence_type"] == "evidence":
            vuln.sanitizer.present = "YES"
            notes.append("ORM parameterisation treated as concrete counter-evidence")
        if report["middleware_auth"]["found"]:
            vuln.authentication.status = "PRESENT"
            notes.append("path-local authentication evidence observed")
        if report["unified_authz"]["found"]:
            vuln.authorization.status = "PRESENT"
            notes.append("path-local authorization evidence observed")

        # Only concrete evidence can lower the proof level. Assumptions are
        # reported for human review but must never manufacture a downgrade.
        concrete = sum(1 for item in report.values() if item["found"] and item["evidence_type"] == "evidence")
        if concrete:
            rank = max(0, _RANK.get(vuln.evidence.level, 1) - 1)
            vuln.evidence.level = _RANK_TO_LEVEL[rank]
            notes.append(f"{concrete} concrete counter-evidence item(s); evidence level trimmed by one")

        if notes:
            log = "\n".join(f"[counter-evidence] {n}" for n in notes)
            vuln.evidence.proof = f"{vuln.evidence.proof}\n{log}" if vuln.evidence.proof else log
        return vuln
