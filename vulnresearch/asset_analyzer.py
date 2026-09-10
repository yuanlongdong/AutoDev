"""Code-asset analysis and attack-surface enumeration (PHASE 1).

Enumerates the reachable entry points of an application – HTTP handlers,
RPC stubs, CLI commands, WebSocket endpoints, queue consumers, cron jobs,
file parsers, upload handlers, admin APIs and internal APIs – and records
whether each asset appears to require authentication.

Pure Python standard library; no target code is executed and no network
requests are made.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .ir import FunctionIR, ProjectIR
from .knowledge_base import AUTH_PATTERNS
from .project_model import ProjectModel


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CodeAsset:
    """A single reachable code asset exposed to (potentially) untrusted input."""

    type: str          # http_handler / rpc / cli / websocket / queue_consumer /
                       # cron / file_parser / upload / admin_api / internal_api
    name: str
    file: str
    line: int
    framework: str = ""
    auth_required: str = "unknown"  # required / missing / unknown


@dataclass
class AttackSurface:
    """The enumerated attack surface of the project."""

    assets: List[CodeAsset] = field(default_factory=list)
    entry_points: List[str] = field(default_factory=list)
    trust_boundaries: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

_HTTP_DECORATOR_RE = re.compile(
    r"@[\w\.]*\s*(?:route|get|post|put|delete|patch|websocket)\s*\(",
    re.IGNORECASE,
)
_ROUTE_PATH_RE = re.compile(
    r"@[\w\.]*\s*(?:route|get|post|put|delete|patch|websocket)\s*\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_CLICK_DECORATOR_RE = re.compile(r"@click\.(?:command|group|option|argument)", re.IGNORECASE)
_GRPC_CALL_RE = re.compile(r"\bgrpc\b", re.IGNORECASE)

# Asset types that are genuinely reachable from the outside world
_ENTRY_TYPES = {"http_handler", "rpc", "websocket", "cli", "queue_consumer",
                "cron", "admin_api", "internal_api"}


# ---------------------------------------------------------------------------
# Asset analyzer
# ---------------------------------------------------------------------------


class AssetAnalyzer:
    """Classifies functions in a :class:`ProjectIR` into code assets."""

    def __init__(self) -> None:
        self._file_cache: Dict[str, List[str]] = {}

    # -- public API --------------------------------------------------------

    def analyze(self, project_ir: ProjectIR, project_model: ProjectModel) -> AttackSurface:
        """Return the enumerated attack surface for *project_ir*."""
        assets: List[CodeAsset] = []
        for fn in project_ir.functions:
            lines = self._read_lines(fn.path)
            decorators = self._extract_decorators(lines, fn.line)
            body = self._body_slice(fn, lines)
            asset = self._classify(fn, decorators, body, project_model)
            if asset is not None:
                assets.append(asset)

        entry_points: List[str] = []
        for a in assets:
            if a.type in _ENTRY_TYPES:
                entry_points.append(f"{a.name} [{a.type}] ({a.file}:{a.line})")

        trust_boundaries = sorted({b["type"] for b in project_model.trust_boundaries})

        return AttackSurface(
            assets=assets,
            entry_points=entry_points,
            trust_boundaries=trust_boundaries,
        )

    # -- source helpers -----------------------------------------------------

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
        idx = def_line - 2  # line directly above `def` (0-based)
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

    # -- classification ----------------------------------------------------

    def _classify(
        self,
        fn: FunctionIR,
        decorators: List[str],
        body: List[str],
        model: ProjectModel,
    ) -> Optional[CodeAsset]:
        name = fn.name
        name_l = name.lower()
        deco_text = " ".join(decorators)
        deco_l = deco_text.lower()
        body_text = "\n".join(body)
        body_l = body_text.lower()
        calls_l = " ".join(c.name for c in fn.calls).lower()
        route_path = self._route_path(decorators)
        auth = self._auth_status(decorators)
        framework = self._guess_framework(model)

        # -- Admin API (highest priority – explicit privilege surface) ------
        if ("admin" in name_l
                or "admin" in route_path.lower()
                or "admin_required" in deco_l):
            return CodeAsset("admin_api", name, fn.path, fn.line, framework, auth)

        # -- Internal API ---------------------------------------------------
        if ("internal" in name_l
                or "_private" in name_l
                or "/internal" in route_path.lower()):
            return CodeAsset("internal_api", name, fn.path, fn.line, framework, auth)

        # -- HTTP handler (decorator based) ---------------------------------
        if _HTTP_DECORATOR_RE.search(deco_text):
            return CodeAsset("http_handler", name, fn.path, fn.line, framework, auth)

        # -- HTTP handler by naming convention ------------------------------
        if any(k in name_l for k in ("handler", "view", "endpoint")):
            return CodeAsset("http_handler", name, fn.path, fn.line, framework, auth)

        # -- WebSocket ------------------------------------------------------
        if (any(k in name_l for k in ("websocket", "ws_handler", "wshandler"))
                or "websocket" in deco_l
                or "socketio" in deco_l):
            return CodeAsset("websocket", name, fn.path, fn.line, framework, auth)

        # -- RPC ------------------------------------------------------------
        if (any(k in name_l for k in ("rpc", "grpc"))
                or _GRPC_CALL_RE.search(calls_l)):
            return CodeAsset("rpc", name, fn.path, fn.line, framework, auth)

        # -- Queue consumer -------------------------------------------------
        if (any(k in name_l for k in ("consume", "consumer", "worker", "on_message", "onmessage"))
                or "consumer" in deco_l):
            return CodeAsset("queue_consumer", name, fn.path, fn.line, framework, auth)

        # -- Cron / scheduled task ------------------------------------------
        if (any(k in name_l for k in ("cron", "job", "scheduled"))
                or any(k in deco_l for k in ("scheduled", "cron", "task", "periodic"))):
            return CodeAsset("cron", name, fn.path, fn.line, framework, auth)

        # -- Upload handler --------------------------------------------------
        if ("request.files" in body_text
                or "file_storage" in body_l
                or "upload" in name_l):
            return CodeAsset("upload", name, fn.path, fn.line, framework, auth)

        # -- File parser ----------------------------------------------------
        if (any(k in name_l for k in ("parse", "load", "read"))
                and any("path" in p.lower() or "file" in p.lower() or "filename" in p.lower()
                        for p in fn.parameters)):
            return CodeAsset("file_parser", name, fn.path, fn.line, framework, auth)

        # -- CLI -------------------------------------------------------------
        if (_CLICK_DECORATOR_RE.search(deco_text)
                or "argparse" in calls_l
                or "argumentparser" in calls_l
                or name_l in ("main", "cli")):
            return CodeAsset("cli", name, fn.path, fn.line, framework, auth)

        return None

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _route_path(decorators: List[str]) -> str:
        for deco in decorators:
            m = _ROUTE_PATH_RE.search(deco)
            if m:
                return m.group(1)
        return ""

    @staticmethod
    def _auth_status(decorators: List[str]) -> str:
        for deco in decorators:
            normalized = deco.split("(")[0].strip()
            for auth_deco in AUTH_PATTERNS["authentication_decorators"]:
                if normalized == auth_deco:
                    return "required"
        return "missing"

    @staticmethod
    def _guess_framework(model: ProjectModel) -> str:
        if model.frameworks:
            return model.frameworks[0]
        return ""
