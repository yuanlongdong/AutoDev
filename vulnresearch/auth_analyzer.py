"""Authentication & authorisation deep analysis (PHASE 6).

Checks are scoped to the vulnerable function and, for data-access findings,
to checks that occur before the relevant query. This prevents an unrelated or
late authorization call from being treated as protection for the sink.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List

from .ir import FunctionIR, ProjectIR
from .knowledge_base import AUTH_PATTERNS
from .asset_analyzer import AttackSurface, CodeAsset

_ID_PARAM_RE = re.compile(r"^(?:user_id|order_id|account_id|doc_id|file_id|id|pk|uuid)$", re.IGNORECASE)
_QUERY_CALL_RE = re.compile(r"\b(execute|raw|query|filter|find_one|find\b|get_or_404|get\b|first\b)\s*\(", re.IGNORECASE)
_CLIENT_CONTROLLED_AUTHZ_RE = re.compile(r"(?:request\.args|request\.form|request\.json|request\.cookies)[^\n]*(?:admin|role|is_staff|superuser|permission)", re.IGNORECASE)
_ROUTE_DECORATOR_RE = re.compile(r"@[\w\.]*\s*(?:route|get|post|put|delete|patch)\s*\(", re.IGNORECASE)
_ROLE_TOKENS = ("roles_required", "user_has_role", "require_admin", "is_admin", "is_superuser")
_PERMISSION_TOKENS = ("permission_required", "has_permission", "has_access")
_OWNERSHIP_TOKENS = ("check_owner", "is_owner", "assert_owner", "belongs_to", "check_permission", "owner_id")
_TENANT_TOKENS = ("check_tenant", "tenant_filter", "assert_tenant", "tenant_id")
_IDENTITY_TOKENS = ("get_current_user", "current_user", "login_user", "session[")


@dataclass
class AuthChain:
    authentication: str = "unknown"
    identity: str = "unknown"
    role: str = "unknown"
    permission: str = "unknown"
    object_ownership: str = "unknown"
    tenant: str = "unknown"
    action: str = "unknown"


@dataclass
class AuthFinding:
    type: str
    description: str
    file: str
    line: int
    function: str
    severity: str


class AuthAnalyzer:
    """Deep authentication / authorisation analyzer."""

    def __init__(self) -> None:
        self._file_cache: Dict[str, List[str]] = {}

    def analyze(self, project_ir: ProjectIR, attack_surface: AttackSurface) -> List[AuthFinding]:
        findings: List[AuthFinding] = []
        fn_index: Dict[tuple, FunctionIR] = {(fn.name, fn.path): fn for fn in project_ir.functions}
        for asset in attack_surface.assets:
            if asset.type not in ("http_handler", "admin_api", "internal_api"):
                continue
            fn = fn_index.get((asset.name, asset.file))
            if fn is None:
                continue
            findings.extend(self._check_asset(asset, fn, self.build_auth_chain(fn)))
        findings.extend(self._find_hidden_endpoints(project_ir))
        return findings

    def build_auth_chain(self, fn: FunctionIR) -> AuthChain:
        lines = self._read_lines(fn.path)
        decorators = self._extract_decorators(lines, fn.line)
        body = self._body_slice(fn, lines)
        body_text = "\n".join(body)
        body_l = body_text.lower()
        return AuthChain(
            authentication="present" if any(deco.split("(")[0].strip() in AUTH_PATTERNS["authentication_decorators"] for deco in decorators) or any(x in body_text for x in AUTH_PATTERNS["authentication_functions"]) else "missing",
            identity="present" if any(x in body_text for x in _IDENTITY_TOKENS) else "missing",
            role="present" if any(x in body_l for x in _ROLE_TOKENS) else "missing",
            permission="present" if any(x in body_l for x in _PERMISSION_TOKENS) else "missing",
            object_ownership="present" if any(x in body_l for x in _OWNERSHIP_TOKENS) else "missing",
            tenant="present" if any(x in body_l for x in _TENANT_TOKENS) else "missing",
            action=fn.name,
        )

    def _check_asset(self, asset: CodeAsset, fn: FunctionIR, chain: AuthChain) -> List[AuthFinding]:
        out: List[AuthFinding] = []
        lines = self._body_slice(fn, self._read_lines(fn.path))
        body_text = "\n".join(lines)
        body_l = body_text.lower()
        query_line = self._first_matching_line(lines, _QUERY_CALL_RE)
        pre_query = lines if query_line is None else lines[:query_line + 1]
        pre_query_text = "\n".join(pre_query).lower()

        if asset.type in ("internal_api", "admin_api") and asset.auth_required != "required":
            out.append(AuthFinding("auth_bypass", f"{asset.type} '{asset.name}' is reachable without any authentication decorator", fn.path, fn.line, fn.name, "High"))

        role_before = any(x in pre_query_text for x in _ROLE_TOKENS)
        permission_before = any(x in pre_query_text for x in _PERMISSION_TOKENS)
        if chain.authentication == "present" and not role_before and not permission_before and (chain.identity == "present" or asset.type == "http_handler"):
            out.append(AuthFinding("missing_authz", f"'{fn.name}' authenticates the caller but no role/permission check is proven before the data-access path", fn.path, fn.line, fn.name, "Medium"))

        id_params = [p for p in fn.parameters if _ID_PARAM_RE.match(p)]
        ownership_before = any(x in pre_query_text for x in _OWNERSHIP_TOKENS)
        if id_params and query_line is not None and not ownership_before:
            out.append(AuthFinding("idor", f"'{fn.name}' uses caller-supplied id parameter(s) {id_params} in a query with no ownership check proven before the query", fn.path, fn.line, fn.name, "High"))

        if _CLIENT_CONTROLLED_AUTHZ_RE.search(body_text):
            out.append(AuthFinding("frontend_authz", f"'{fn.name}' makes an authorisation decision based on client-supplied request parameters", fn.path, fn.line, fn.name, "Medium"))

        if asset.type == "admin_api" and not role_before:
            out.append(AuthFinding("priv_esc", f"admin asset '{fn.name}' exposes privileged functionality without a role/admin check proven before the data-access path", fn.path, fn.line, fn.name, "High"))

        tenant_before = any(x in pre_query_text for x in _TENANT_TOKENS)
        if ("tenant" in body_l or "account" in body_l) and query_line is not None and not tenant_before:
            out.append(AuthFinding("tenant_break", f"'{fn.name}' accesses tenant/account-scoped data without a tenant isolation filter proven before the query", fn.path, fn.line, fn.name, "High"))
        return out

    def _find_hidden_endpoints(self, project_ir: ProjectIR) -> List[AuthFinding]:
        out: List[AuthFinding] = []
        for fn in project_ir.functions:
            name_l = fn.name.lower()
            if not any(k in name_l for k in ("handler", "view", "endpoint")):
                continue
            decorators = self._extract_decorators(self._read_lines(fn.path), fn.line)
            if not any(_ROUTE_DECORATOR_RE.search(d) for d in decorators):
                out.append(AuthFinding("hidden_endpoint", f"handler-shaped function '{fn.name}' has no route decorator; it may be reachable directly", fn.path, fn.line, fn.name, "Low"))
        return out

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
        return lines[max(0, fn.line - 1):min(len(lines), fn.end_line)]

    @staticmethod
    def _first_matching_line(lines: List[str], pattern: re.Pattern[str]):
        for idx, line in enumerate(lines):
            if pattern.search(line):
                return idx
        return None
