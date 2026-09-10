"""Project modelling and trust-boundary identification (PHASE 0).

This module builds a lightweight structural model of an analysed project:
detected languages, frameworks, build system, package manager, datastores,
authentication / authorisation posture, deployment target, and the points
where code crosses trust boundaries (external input -> database / filesystem /
network / deserialisation).

The implementation is pure Python standard library, never executes the
analysed code and never performs network I/O.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .knowledge_base import (
    AUTH_PATTERNS,
    FRAMEWORK_SIGNATURES,
    TRUST_BOUNDARY_TYPES,
)
from .ir import ProjectIR


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ProjectModel:
    """Structural model of the target project."""

    language: str = "unknown"
    frameworks: List[str] = field(default_factory=list)
    build_system: str = "unknown"
    package_manager: str = "unknown"
    databases: List[str] = field(default_factory=list)
    message_queues: List[str] = field(default_factory=list)
    caches: List[str] = field(default_factory=list)
    authentication: str = "unknown"
    authorization: str = "unknown"
    deployment: str = "unknown"
    trust_boundaries: List[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Detection tables (pure literals, stdlib only)
# ---------------------------------------------------------------------------

LANGUAGE_EXT: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".cs": "csharp",
}

# import-substring -> datastore friendly name
DB_IMPORTS: Dict[str, str] = {
    "psycopg2": "postgresql",
    "psycopg": "postgresql",
    "asyncpg": "postgresql",
    "sqlalchemy": "sqlalchemy",
    "pymongo": "mongodb",
    "mongoengine": "mongodb",
    "motor": "mongodb",
    "redis": "redis",
    "aioredis": "redis",
    "sqlite3": "sqlite",
    "pymysql": "mysql",
    "mysql.connector": "mysql",
    "cx_Oracle": "oracle",
    "sqlite": "sqlite",
}

QUEUE_IMPORTS: Dict[str, str] = {
    "celery": "celery",
    "kombu": "kombu",
    "pika": "rabbitmq",
    "confluent_kafka": "kafka",
    "kafka": "kafka",
    "stomp": "stomp",
    "rq": "redis-queue",
    "gearman": "gearman",
}

CACHE_IMPORTS: Dict[str, str] = {
    "redis": "redis",
    "aioredis": "redis",
    "memcache": "memcached",
    "pylibmc": "memcached",
    "flask_caching": "flask-cache",
    "django.core.cache": "django-cache",
}

# Filenames that hint at a build / packaging tool
BUILD_FILES: Dict[str, Dict[str, str]] = {
    "pyproject.toml": {"build_system": "setuptools/poetry", "package_manager": "pip"},
    "setup.py": {"build_system": "setuptools", "package_manager": "pip"},
    "setup.cfg": {"build_system": "setuptools", "package_manager": "pip"},
    "requirements.txt": {"build_system": "pip", "package_manager": "pip"},
    "Pipfile": {"build_system": "pipenv", "package_manager": "pipenv"},
    "poetry.lock": {"build_system": "poetry", "package_manager": "poetry"},
    "package.json": {"build_system": "npm", "package_manager": "npm"},
    "yarn.lock": {"build_system": "yarn", "package_manager": "yarn"},
    "Pnpmfile.cjs": {"build_system": "pnpm", "package_manager": "pnpm"},
    "Makefile": {"build_system": "make", "package_manager": "unknown"},
    "CMakeLists.txt": {"build_system": "cmake", "package_manager": "unknown"},
}

DEPLOY_FILES: Dict[str, str] = {
    "Dockerfile": "docker",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    "Procfile": "heroku",
    "kustomization.yaml": "kubernetes",
    "deployment.yaml": "kubernetes",
}

# Regexes used to locate trust-boundary crossing points
_HTTP_HANDLER_RE = re.compile(
    r"@[\w\.]*\s*(?:route|get|post|put|delete|patch|websocket|errorhandler)\s*\(",
    re.IGNORECASE,
)
_DB_QUERY_RE = re.compile(
    r"(?:cursor\.)?(?:execute|executemany|raw|query|filter|find_one|find\(|insert_one|"
    r"insert_many|update_one|update_many|delete_one|delete_many)\s*\(",
    re.IGNORECASE,
)
_FILE_OP_RE = re.compile(
    r"\bopen\s*\(|\bread_text\s*\(|\bwrite_text\s*\(|send_file\s*\(|secure_filename\s*\(|"
    r"\.save\s*\(|extractall\s*\(",
    re.IGNORECASE,
)
_NET_REQ_RE = re.compile(
    r"requests\.(?:get|post|put|delete|head|options|request)|urllib\.request\.(?:urlopen|Request)|"
    r"http\.client|aiohttp\.ClientSession",
    re.IGNORECASE,
)
_DESERIAL_RE = re.compile(
    r"pickle\.(?:load|loads|Unpickler)|yaml\.load\s*\(|marshal\.loads\s*\(|jsonpickle",
    re.IGNORECASE,
)
_REDIRECT_RE = re.compile(r"\b(?:redirect|HttpResponseRedirect)\s*\(", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Project modeler
# ---------------------------------------------------------------------------


class ProjectModeler:
    """Builds a :class:`ProjectModel` from a source tree root."""

    EXCLUDES = {
        ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
        "dist", "build", "__pycache__", ".tox", ".mypy_cache",
    }

    def build(self, root: str, project_ir: Optional[ProjectIR] = None) -> ProjectModel:
        """Analyse *root* and return a populated :class:`ProjectModel`.

        *project_ir* may be supplied to enrich boundary detection; when it is
        ``None`` the modeler falls back to pure source scanning.
        """
        root_path = Path(root).resolve()
        model = ProjectModel()

        py_files: List[Path] = []
        all_files: List[Path] = []
        for path in root_path.rglob("*"):
            if not path.is_file():
                continue
            if any(part in self.EXCLUDES for part in path.parts):
                continue
            all_files.append(path)
            if path.suffix.lower() == ".py":
                py_files.append(path)

        model.language = self._detect_language(all_files)
        model.build_system, model.package_manager, model.deployment = self._detect_build(all_files)

        frameworks: set = set()
        databases: set = set()
        queues: set = set()
        caches: set = set()
        auth_seen: set = set()
        authz_seen: set = set()

        for pf in py_files:
            try:
                text = pf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for fw, signatures in FRAMEWORK_SIGNATURES.items():
                if any(sig in text for sig in signatures):
                    frameworks.add(fw)

            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not (line.startswith("import ") or line.startswith("from ")):
                    continue
                for mod, name in DB_IMPORTS.items():
                    if mod in line:
                        databases.add(name)
                for mod, name in QUEUE_IMPORTS.items():
                    if mod in line:
                        queues.add(name)
                for mod, name in CACHE_IMPORTS.items():
                    if mod in line:
                        caches.add(name)

            for deco in AUTH_PATTERNS["authentication_decorators"]:
                if deco in text:
                    auth_seen.add(deco)
            for fn in AUTH_PATTERNS["authentication_functions"]:
                if fn in text:
                    auth_seen.add(fn)
            for deco in AUTH_PATTERNS["authorization_decorators"]:
                if deco in text:
                    authz_seen.add(deco)
            for fn in AUTH_PATTERNS["authorization_functions"]:
                if fn in text:
                    authz_seen.add(fn)

        model.frameworks = sorted(frameworks)
        model.databases = sorted(databases)
        model.message_queues = sorted(queues)
        model.caches = sorted(caches)
        model.authentication = "present" if auth_seen else "none"
        model.authorization = "present" if authz_seen else "none"

        model.trust_boundaries = self._identify_trust_boundaries(root_path, py_files, project_ir)
        return model

    # -- internal helpers ---------------------------------------------------

    def _detect_language(self, files: List[Path]) -> str:
        counts: Dict[str, int] = {}
        for f in files:
            lang = LANGUAGE_EXT.get(f.suffix.lower())
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
        if not counts:
            return "unknown"
        return max(counts, key=counts.get)

    def _detect_build(self, files: List[Path]):
        build_system = "unknown"
        package_manager = "unknown"
        deployment = "unknown"
        names = {f.name for f in files}
        # directory-based deployment hints
        for f in files:
            if f.name in DEPLOY_FILES:
                deployment = DEPLOY_FILES[f.name]
        for name, info in BUILD_FILES.items():
            if name in names:
                if build_system == "unknown":
                    build_system = info["build_system"]
                if package_manager == "unknown":
                    package_manager = info["package_manager"]
        # pyproject.toml may be poetry or setuptools
        if "pyproject.toml" in names:
            pp = next((f for f in files if f.name == "pyproject.toml"), None)
            if pp is not None:
                try:
                    head = pp.read_text(encoding="utf-8", errors="replace")[:2000]
                except OSError:
                    head = ""
                if "poetry" in head:
                    build_system = "poetry"
                    package_manager = "poetry"
        return build_system, package_manager, deployment

    def _identify_trust_boundaries(
        self,
        root_path: Path,
        py_files: List[Path],
        project_ir: Optional[ProjectIR],
    ) -> List[dict]:
        boundaries: List[dict] = []
        seen: set = set()

        def add(btype: str, description: str, location: str):
            key = (btype, description, location)
            if key in seen:
                return
            seen.add(key)
            boundaries.append({"type": btype, "description": description, "location": location})

        for pf in py_files:
            try:
                lines = pf.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            try:
                rel = str(pf.relative_to(root_path))
            except ValueError:
                rel = str(pf)
            for idx, line in enumerate(lines, 1):
                if _HTTP_HANDLER_RE.search(line):
                    add("Network Boundary", "HTTP entry point accepting external input", f"{rel}:{idx}")
                if _DB_QUERY_RE.search(line):
                    add("Database Boundary", "Database access crossing trust boundary", f"{rel}:{idx}")
                if _FILE_OP_RE.search(line):
                    add("Filesystem Boundary", "Filesystem access crossing trust boundary", f"{rel}:{idx}")
                if _NET_REQ_RE.search(line):
                    add("Network Boundary", "Outbound network request to remote service", f"{rel}:{idx}")
                if _DESERIAL_RE.search(line):
                    add("Serialization Boundary", "Untrusted deserialization crossing trust boundary", f"{rel}:{idx}")
                if _REDIRECT_RE.search(line):
                    add("Network Boundary", "Redirect to caller-controlled destination", f"{rel}:{idx}")

        # Enrich from project IR when available: functions with both a source
        # and a sink cross a trust boundary by construction.
        if project_ir is not None:
            for fn in project_ir.functions:
                if fn.sources and fn.sinks:
                    add(
                        "Trust Boundary",
                        f"Function '{fn.name}' bridges untrusted input to a dangerous sink",
                        f"{fn.path}:{fn.line}",
                    )
        return boundaries


# ---------------------------------------------------------------------------
# Summary helper
# ---------------------------------------------------------------------------


def trust_boundary_summary(model: ProjectModel) -> str:
    """Return a human-readable text summary of the project model."""
    lines: List[str] = []
    lines.append(f"Language: {model.language}")
    lines.append(f"Frameworks: {', '.join(model.frameworks) or 'none detected'}")
    lines.append(f"Build system: {model.build_system}")
    lines.append(f"Package manager: {model.package_manager}")
    if model.databases:
        lines.append(f"Databases: {', '.join(model.databases)}")
    if model.message_queues:
        lines.append(f"Message queues: {', '.join(model.message_queues)}")
    if model.caches:
        lines.append(f"Caches: {', '.join(model.caches)}")
    lines.append(f"Authentication: {model.authentication}")
    lines.append(f"Authorization: {model.authorization}")
    lines.append(f"Deployment: {model.deployment}")
    lines.append(f"Trust boundaries identified: {len(model.trust_boundaries)}")
    by_type: Dict[str, int] = {}
    for b in model.trust_boundaries:
        by_type[b["type"]] = by_type.get(b["type"], 0) + 1
    for btype, count in sorted(by_type.items()):
        lines.append(f"  - {btype}: {count} crossing point(s)")
    return "\n".join(lines)
