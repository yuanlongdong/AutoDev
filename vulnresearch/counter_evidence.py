"""Counter-evidence engine (PHASE 21).

While other passes hunt for *reasons a vulnerability exists*, this one does
the opposite: it actively searches the intermediate representation for reasons
the finding might be a **false positive** — hidden sanitizers, global auth
middleware, unified authorisation, ORM auto-parameterisation, disabled
features and so on.

Every finding carries an explicit ``evidence_type``:

* ``"evidence"`` – the signal was observed directly in the supplied IR / source
  corpus (e.g. a call to ``markupsafe.escape`` literally appears in the body);
* ``"assumption"`` – the signal is inferred from a framework heuristic and may
  need manual confirmation.

The module never executes target code and never performs network I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .knowledge_base import AUTH_PATTERNS, SANITIZERS
from .models import Vulnerability

# Flattened sanitizer name list for substring search.
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
    return {"found": found, "description": description,
            "evidence_type": evidence_type}


class CounterEvidenceEngine:
    """Look for reasons a candidate vulnerability might not be exploitable."""

    # -- analysis -----------------------------------------------------------

    def analyze(self, vuln: Vulnerability, ir_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Run every counter-evidence check and return a structured report."""
        corpus = self._corpus(vuln, ir_data)
        context: Dict[str, Any] = ir_data.get("context", {}) or {}

        return {
            "hidden_sanitizer": self._check_hidden_sanitizer(corpus),
            "middleware_auth": self._check_middleware_auth(corpus),
            "unified_authz": self._check_unified_authz(corpus),
            "service_layer_check": self._check_service_layer(ir_data, corpus),
            "unreachable_path": self._check_unreachable_path(vuln),
            "disabled_config": self._check_disabled_config(context),
            "framework_auto_encoding": self._check_framework_auto_encoding(corpus),
            "orm_auto_parameterization": self._check_orm_auto_parameterization(vuln, corpus),
        }

    # -- corpus -------------------------------------------------------------

    @staticmethod
    def _corpus(vuln: Vulnerability, ir_data: Dict[str, Any]) -> str:
        """Assemble a searchable text corpus without executing anything."""
        parts: List[str] = [vuln.snippet, vuln.sink.type, vuln.sink.location]
        parts.extend(step.step for step in vuln.data_flow)
        parts.extend(step.transformation for step in vuln.data_flow)
        parts.append(str(ir_data.get("source_text", "")))
        parts.append(str(ir_data.get("body", "")))
        for func in ir_data.get("functions", []) or []:
            if isinstance(func, dict):
                parts.append(str(func.get("name", "")))
                for call in func.get("calls", []) or []:
                    if isinstance(call, dict):
                        parts.append(str(call.get("name", "")))
                    else:
                        parts.append(str(call))
        return "\n".join(p for p in parts if p)

    # -- individual checks --------------------------------------------------

    def _check_hidden_sanitizer(self, corpus: str) -> Dict[str, Any]:
        hits = [t for t in _SANITIZER_TOKENS if t and t in corpus]
        if hits:
            return _hit(
                True,
                f"Known sanitizer(s) present in data flow: {', '.join(hits[:5])}",
                "evidence",
            )
        return _hit(False, "No known sanitizer found on the data flow", "evidence")

    def _check_middleware_auth(self, corpus: str) -> Dict[str, Any]:
        hits = [d for d in AUTH_PATTERNS["authentication_decorators"] if d in corpus]
        if hits:
            return _hit(
                True,
                f"Global authentication decorator/middleware observed: {', '.join(hits)}",
                "evidence",
            )
        return _hit(False, "No authentication decorator/middleware found", "evidence")

    def _check_unified_authz(self, corpus: str) -> Dict[str, Any]:
        hits = [f for f in AUTH_PATTERNS["authorization_functions"] if f in corpus]
        if hits:
            return _hit(
                True,
                f"Unified authorization check observed: {', '.join(hits)}",
                "evidence",
            )
        return _hit(False, "No unified authorization check found", "evidence")

    def _check_service_layer(self, ir_data: Dict[str, Any],
                             corpus: str) -> Dict[str, Any]:
        funcs = ir_data.get("functions", []) or []
        for func in funcs:
            if not isinstance(func, dict):
                continue
            name = str(func.get("name", ""))
            if "service" not in name.lower():
                continue
            blob = "\n".join(
                str(c.get("name", "")) if isinstance(c, dict) else str(c)
                for c in (func.get("calls", []) or [])
            )
            if any(t in blob for t in _SANITIZER_TOKENS) or \
                    any(a in blob for a in AUTH_PATTERNS["authorization_functions"]):
                return _hit(
                    True,
                    f"Service-layer function '{name}' performs an additional check",
                    "assumption",
                )
        if "service" in corpus.lower():
            return _hit(False, "Service layer present but no extra check observed", "assumption")
        return _hit(False, "No dedicated service layer visible in the IR", "assumption")

    @staticmethod
    def _check_unreachable_path(vuln: Vulnerability) -> Dict[str, Any]:
        if vuln.reachability.status == "UNREACHABLE":
            return _hit(True, "Reachability analysis marks the path UNREACHABLE", "evidence")
        return _hit(False, "Tainted path is not marked unreachable", "evidence")

    @staticmethod
    def _check_disabled_config(context: Dict[str, Any]) -> Dict[str, Any]:
        if context.get("feature_enabled") is False or \
                context.get("enabled") is False or \
                context.get("disabled") is True:
            return _hit(True, "Configuration disables the affected feature", "evidence")
        return _hit(False, "Feature appears enabled", "evidence")

    @staticmethod
    def _check_framework_auto_encoding(corpus: str) -> Dict[str, Any]:
        lowered = corpus.lower()
        if "django" in lowered or "from django" in lowered:
            return _hit(
                True,
                "Django detected – templates auto-escape by default (assumption; "
                "verify | safe / mark_safe usage)",
                "assumption",
            )
        if "jinja" in lowered or "flask" in lowered or "render_template" in lowered:
            return _hit(
                True,
                "Jinja2/Flask template detected – autoescape is usually enabled "
                "(assumption; verify autoescape setting)",
                "assumption",
            )
        return _hit(False, "No framework auto-encoding guarantee detected", "assumption")

    @staticmethod
    def _check_orm_auto_parameterization(vuln: Vulnerability,
                                        corpus: str) -> Dict[str, Any]:
        sink_text = f"{vuln.sink.type} {corpus}".lower()
        is_orm = any(h in sink_text for h in _ORM_METHOD_HINTS)
        is_raw = any(h.lower() in sink_text for h in _RAW_SQL_HINTS)
        if is_orm and not is_raw:
            return _hit(
                True,
                "Sink looks like an ORM method (filter/get/query) rather than raw SQL – "
                "arguments are likely parameterised",
                "evidence",
            )
        return _hit(False, "Sink is not clearly an auto-parameterised ORM call", "evidence")

    # -- application --------------------------------------------------------

    def apply_counter_evidence(self, vuln: Vulnerability,
                               ir_data: Dict[str, Any]) -> Vulnerability:
        """Fold the counter-evidence report back onto the vulnerability."""
        report = self.analyze(vuln, ir_data)
        notes: List[str] = []

        if report["hidden_sanitizer"]["found"] or \
                report["orm_auto_parameterization"]["found"]:
            vuln.sanitizer.present = "YES"
            vuln.sanitizer.description = "; ".join(
                report[k]["description"]
                for k in ("hidden_sanitizer", "orm_auto_parameterization")
                if report[k]["found"]
            )
            notes.append("sanitizer marked present by counter-evidence")

        if report["middleware_auth"]["found"]:
            vuln.authentication.status = "PRESENT"
            notes.append("authentication middleware observed")

        if report["unified_authz"]["found"]:
            vuln.authorization.status = "PRESENT"
            notes.append("unified authorization check observed")

        concrete = sum(
            1 for item in report.values()
            if item["found"] and item["evidence_type"] == "evidence"
        )
        if concrete:
            # A concrete counter-argument weakens the proven chain: trim one rung.
            rank = max(0, _RANK.get(vuln.evidence.level, 1) - 1)
            vuln.evidence.level = _RANK_TO_LEVEL[rank]
            notes.append(
                f"{concrete} concrete counter-evidence item(s); evidence level trimmed by one"
            )

        if notes:
            log = "\n".join(f"[counter-evidence] {n}" for n in notes)
            vuln.evidence.proof = (
                f"{vuln.evidence.proof}\n{log}" if vuln.evidence.proof else log
            )
        return vuln
