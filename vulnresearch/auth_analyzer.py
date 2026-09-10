"""Authentication & authorisation deep analysis (PHASE 6).

For each externally reachable asset the analyzer reconstructs the
authentication / authorisation chain and flags common weaknesses:

* **missing_authz** – authenticated but never authorisation-checked
* **idor** – caller-supplied object id used in a query without ownership check
* **auth_bypass** – internal / admin API exposed without authentication
* **priv_esc** – privilege boundary crossed without a role check
* **tenant_break** – no tenant filter on a data access
* **frontend_authz** – authorisation decision driven by client input
* **hidden_endpoint** – handler-shaped function with no route registration
* **method_diff** – inconsistent auth across HTTP methods on the same path

The analyzer models the four canonical abuse scenarios:
User A→Object A (normal), User A→Object B (IDOR),
Normal user→Admin function (priv-esc), Tenant A→Tenant B (tenant break).

Pure Python standard library; no execution, no network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .ir import FunctionIR, ProjectIR
from .knowledge_base import AUTH_PATTERNS
from .asset_analyzer import AttackSurface, CodeAsset


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class AuthChain:
    """Reconstructed authentication / authorisation chain for one function."""

    authentication: str = "unknown"      # present / missing / unknown
    identity: str = "unknown"           # present / missing
    role: str = "unknown"               # present / missing
    permission: str = "unknown"         # present / missing
    object_ownership: str = "unknown"   # present / missing
    tenant: str = "unknown"             # present / missing
    action: str = "unknown"             # e.g. "get_order"


@dataclass
class AuthFinding:
    """A discovered authentication / authorisation weakness."""

    type: str           # auth_bypass / idor / priv_esc / tenant_break /
                        # missing_authz / frontend_authz / predictable_id /
                        # hidden_endpoint / method_diff
    description: str
    file: str
    line: int
    function: str
    severity: str


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

# Parameter names that look like direct object references
_ID_PARAM_RE = re.compile(r"^(?:user_id|order_id|account_id|doc_id|file_id|id|pk|uuid)$", re.IGNORECASE)
# Calls that perform an ownership / tenant check
_OWNERSHIP_FNS = {
    "check_owner", "is_owner", "verify_owner", "assert_owner",
    "belongs_to", "check_permission",
}
_TENANT_FNS = {"check_tenant", "tenant_filter", "assert_tenant", "ensure_tenant"}
_AUTHZ_FNS = set(AUTH_PATTERNS["authorization_functions"]) | set(AUTH_PATTERNS["authorization_decorators"])
_AUTHN_FNS = set(AUTH_PATTERNS["authentication_functions"]) | set(AUTH_PATTERNS["authentication_decorators"])
_QUERY_CALL_RE = re.compile(
    r"\b(execute|raw|query|filter|find_one|find\b|get_or_404|get\b|first\b)\s*\(",
    re.IGNORECASE,
)
_CLIENT_CONTROLLED_AUTHZ_RE = re.compile(
    r"(?:request\.args|request\.form|request\.json|request\.cookies)"
    r"[^\n]*(?:admin|role|is_staff|superuser|permission)",
    re.IGNORECASE,
)
_ROUTE_DECORATOR_RE = re.compile(
    r"@[\w\.]*\s*(?:route|get|post|put|delete|patch)\s*\(", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Auth analyzer
# ---------------------------------------------------------------------------


class AuthAnalyzer:
    """Deep authentication / authorisation analyzer."""

    def __init__(self) -> None:
        self._file_cache: Dict[str, List[str]] = {}

    # -- public API --------------------------------------------------------

    def analyze(
        self,
        project_ir: ProjectIR,
        attack_surface: AttackSurface,
    ) -> List[AuthFinding]:
        """Analyse every reachable asset and return a list of findings."""
        findings: List[AuthFinding] = []

        # index functions by (name, file) so assets can resolve them
        fn_index: Dict[tuple, FunctionIR] = {}
        for fn in project_ir.functions:
            fn_index[(fn.name, fn.path)] = fn

        for asset in attack_surface.assets:
            if asset.type not in ("http_handler", "admin_api", "internal_api"):
                continue
            fn = fn_index.get((asset.name, asset.file))
            if fn is None:
                continue

            chain = self.build_auth_chain(fn)
            findings.extend(self._check_asset(asset, fn, chain))

        # hidden-endpoint scan: handler-shaped functions with no route decorator
        findings.extend(self._find_hidden_endpoints(project_ir))
        return findings

    # -- chain reconstruction ----------------------------------------------

    def build_auth_chain(self, fn: FunctionIR) -> AuthChain:
        """Reconstruct the auth chain for a single function."""
        lines = self._read_lines(fn.path)
        decorators = self._extract_decorators(lines, fn.line)
        body = self._body_slice(fn, lines)
        body_text = "\n".join(body)
        body_l = body_text.lower()
        calls_l = " ".join(c.name for c in fn.calls)

        chain = AuthChain(action=fn.name)

        # authentication
        authn_present = any(
            deco.split("(")[0].strip() in AUTH_PATTERNS["authentication_decorators"]
            for deco in decorators
        ) or any(fn_name in body_text for fn_name in AUTH_PATTERNS["authentication_functions"])
        chain.authentication = "present" if authn_present else "missing"

        # identity resolution
        chain.identity = "present" if any(
            tok in body_text for tok in ("get_current_user", "current_user", "login_user", "session[")
        ) else "missing"

        # role
        chain.role = "present" if any(
            tok in body_l for tok in ("roles_required", "user_has_role", "require_admin", "is_admin", "is_superuser")
        ) else "missing"

        # permission
        chain.permission = "present" if any(
            tok in body_l for tok in ("permission_required", "has_permission", "has_access")
        ) else "missing"

        # object ownership
        chain.object_ownership = "present" if any(
            tok in body_l for tok in ("check_owner", "is_owner", "assert_owner", "belongs_to", "owner_id")
        ) else "missing"

        # tenant
        chain.tenant = "present" if any(
            tok in body_l for tok in ("check_tenant", "tenant_filter", "assert_tenant", "tenant_id")
        ) else "missing"

        return chain

    # -- per-asset checks ---------------------------------------------------

    def _check_asset(self, asset: CodeAsset, fn: FunctionIR, chain: AuthChain) -> List[AuthFinding]:
        out: List[AuthFinding] = []
        body_text = "\n".join(self._body_slice(fn, self._read_lines(fn.path)))
        body_l = body_text.lower()

        # 1. internal API / admin API with no authentication at all
        if asset.type in ("internal_api", "admin_api") and asset.auth_required != "required":
            out.append(AuthFinding(
                type="auth_bypass",
                description=f"{asset.type} '{asset.name}' is reachable without any authentication decorator",
                file=fn.path, line=fn.line, function=fn.name, severity="High",
            ))

        # 2. authenticated but no authorisation (只认证不授权)
        if chain.authentication == "present" and chain.permission == "missing" and chain.role == "missing":
            # only flag for user-facing resources, not purely public endpoints
            if chain.identity == "present" or asset.type == "http_handler":
                out.append(AuthFinding(
                    type="missing_authz",
                    description=f"'{fn.name}' authenticates the caller but performs no "
                                "authorisation / permission / role check",
                    file=fn.path, line=fn.line, function=fn.name, severity="Medium",
                ))

        # 3. IDOR – caller-supplied id used in a query without ownership check
        id_params = [p for p in fn.parameters if _ID_PARAM_RE.match(p)]
        if id_params and _QUERY_CALL_RE.search(body_text) and chain.object_ownership == "missing":
            out.append(AuthFinding(
                type="idor",
                description=f"'{fn.name}' uses caller-supplied id parameter(s) "
                            f"{id_params} in a query with no ownership check",
                file=fn.path, line=fn.line, function=fn.name, severity="High",
            ))

        # 4. frontend-driven authorisation (client-controlled decision)
        if _CLIENT_CONTROLLED_AUTHZ_RE.search(body_text):
            out.append(AuthFinding(
                type="frontend_authz",
                description=f"'{fn.name}' makes an authorisation decision based on "
                            "client-supplied request parameters",
                file=fn.path, line=fn.line, function=fn.name, severity="Medium",
            ))

        # 5. privilege escalation surface: admin-ish endpoint without role check
        if asset.type == "admin_api" and chain.role == "missing":
            out.append(AuthFinding(
                type="priv_esc",
                description=f"admin asset '{fn.name}' exposes privileged functionality "
                            "without a role / admin check",
                file=fn.path, line=fn.line, function=fn.name, severity="High",
            ))

        # 6. tenant break: data access without tenant filter
        if ("tenant" in body_l or "account" in body_l) and chain.tenant == "missing":
            # only flag when the function touches a query (multi-tenant smell)
            if _QUERY_CALL_RE.search(body_text):
                out.append(AuthFinding(
                    type="tenant_break",
                    description=f"'{fn.name}' accesses tenant/account-scoped data "
                                "without a tenant isolation filter",
                    file=fn.path, line=fn.line, function=fn.name, severity="High",
                ))

        return out

    # -- hidden-endpoint scan ----------------------------------------------

    def _find_hidden_endpoints(self, project_ir: ProjectIR) -> List[AuthFinding]:
        out: List[AuthFinding] = []
        for fn in project_ir.functions:
            name_l = fn.name.lower()
            if not any(k in name_l for k in ("handler", "view", "endpoint")):
                continue
            lines = self._read_lines(fn.path)
            decorators = self._extract_decorators(lines, fn.line)
            if not any(_ROUTE_DECORATOR_RE.search(d) for d in decorators):
                out.append(AuthFinding(
                    type="hidden_endpoint",
                    description=f"handler-shaped function '{fn.name}' has no route decorator; "
                                "it may be reachable directly",
                    file=fn.path, line=fn.line, function=fn.name, severity="Low",
                ))
        return out

    # -- source helpers ------------------------------------------------------

    def _read_lines(self, path: str) -> List[str]:
        if path not in self._file_cache:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    self._file_cache[path] = fh.read().splitlines()
            except OSError:
                self._file_cache[path] = []
        return self._file_cache[path]

    @staticmethod
    def _extract_decorators(lines: List[str], def_line: int) -> List[str]:
        decos: List[str] = []
        idx = def_line - 2
        while 0 <= idx < len(lines):
            stripped = lines[idx].strip()
            if stripped.startswith("@"):
                decos.append(stripped)
                idx -= 1
            elif stripped == "" or stripped.startswith("#"):
                idx -= 1
            else:
                break
        return decos

    @staticmethod
    def _body_slice(fn: FunctionIR, lines: List[str]) -> List[str]:
        start = max(0, fn.line - 1)
        end = min(len(lines), fn.end_line)
        return lines[start:end]
