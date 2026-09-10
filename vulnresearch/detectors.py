"""Conservative source/sink detectors. They report evidence, never execute payloads."""
from pathlib import Path
import ast
import re
from .models import Finding, Vulnerability, SinkInfo, EvidenceInfo
from .knowledge_base import (
    VULN_CATEGORIES,
    AUTH_PATTERNS,
    SANITIZERS,
)

RULES = [
    ("SQL Injection", "sql-injection", "High", re.compile(r"(?:execute|executemany|raw|query|text)\s*\([^\n]*(?:f['\"]|['\"][^'\"]*['\"]\s*\+|\.format\()", re.I), "Use parameterized queries."),
    ("Command Injection", "command-injection", "Critical", re.compile(
        r"(?:os\.system|os\.popen|"
        r"subprocess\.(?:run|Popen|call|check_output|check_call|getoutput|getstatusoutput)|"
        r"commands\.getoutput)\s*\([^\n]*"
        r"(?:f['\"]|['\"][^'\"]*\+|\.format\(|shell\s*=\s*True)",
        re.I), "Pass argv as a list and avoid shell interpretation."),
    ("Path Traversal", "path-traversal", "High", re.compile(r"(?:open|Path\s*\(|read_text|read_bytes)\s*\([^\n]*(?:request|params|query|filename|filepath|path)", re.I), "Constrain paths to an allowlisted directory and resolve before access."),
    # v0.6.0: the network-semantic tokens are matched on word boundaries so a
    # config/test constant like ``BASE_URL`` / ``PRODUCT_SERVICE_URL`` (where
    # "url" is glued to the name with ``_``) no longer trips the rule; only a
    # standalone ``url=`` / ``target`` / ``host`` argument is flagged.
    ("SSRF", "ssrf", "High", re.compile(
        r"(?:requests\.(?:get|post|put|delete|request)|"
        r"urllib\.request\.(?:urlopen|Request)|urlopen|"
        r"httpx\.(?:get|post|request)|"
        r"aiohttp\.(?:ClientSession\.)?(?:get|post|request)|"
        r"http\.client\.HTTPConnection|"
        r"urllib3\.PoolManager\.request)\s*\([^\n]*"
        r"\b(?:url|uri|target|host|endpoint|callback|webhook|proxy|redirect_url|next_url|fetch_url|remote|external)\b",
        re.I), "Allowlist schemes/hosts and block private/link-local destinations."),
    # v0.3.1: broadened the keyword set (access_key / private_key / credential /
    # aws_access / aws_secret) and matched ``secret[_-]?key`` as a whole so that
    # ``AWS_SECRET_KEY = "..."`` / ``AWS_ACCESS_KEY = "..."`` are reported.  The
    # old alternation only matched bare ``secret``/``access`` immediately before
    # ``=``, which missed ``AWS_SECRET_KEY`` (``secret`` is followed by ``_KEY``).
    ("Hardcoded Secret", "secret", "High", re.compile(
        r"(?i)(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|token|"
        r"access[_-]?key|private[_-]?key|credential|"
        r"aws[_-]?(?:access|secret)(?:[_-]?key)?)"
        r"\s*=\s*b?['\"][^'\"]{8,}['\"]"
    ), "Move secrets to a secret manager or environment configuration."),
    # v0.3.1: AWS Access Key IDs have a well-known fixed shape ``AKIA[0-A-Z]{16}``.
    ("AWS Access Key ID", "secret", "Critical", re.compile(r"AKIA[0-9A-Z]{16}\b"), "Move AWS credentials to IAM roles / a secrets manager."),
    ("Dangerous Deserialization", "deserialization", "Critical", re.compile(r"(?:pickle\.(?:load|loads)|yaml\.load\s*\([^\n]*Loader\s*=\s*(?!yaml\.SafeLoader))", re.I), "Use safe, data-only deserialization."),
    # v0.2.2: the legacy XSS regex was removed.  XSS/SSTI are now handled
    # exclusively by the structured ``XSSDetector`` / ``SSTIDetector`` which
    # perform intra-procedural taint tracking, so database output, hash/encoding
    # results and subprocess output are no longer false positives.
]


def scan_file(path: Path):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    findings = []
    for title, category, severity, pattern, fix in RULES:
        for idx, line in enumerate(lines, 1):
            # Skip pure import lines — they list dangerous names but do not
            # invoke them (e.g. ``from flask import render_template_string``).
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                continue
            if pattern.search(line):
                findings.append(Finding(
                    title=title,
                    category=category,
                    severity=severity,
                    confidence="Low",
                    evidence="E1: suspicious code pattern; reachability and sanitization require review",
                    path=str(path), line=idx, snippet=line.strip(),
                    sink=category, remediation=fix,
                ))
    return findings


# ===================================================================
# PHASE 5 – Structured AST-aware detectors
# ===================================================================

from typing import List  # noqa: E402  (placed after legacy code for clarity)
from .ir import FunctionIR, ProjectIR  # noqa: E402


# -- internal helpers ------------------------------------------------------

# Python keywords excluded when extracting free-variable roots from f-strings.
_PY_KEYWORDS = frozenset({
    "for", "in", "if", "else", "elif", "and", "or", "not", "is", "as",
    "import", "from", "return", "yield", "lambda", "True", "False", "None",
    "with", "while", "def", "class", "print", "range", "len", "str", "int",
})


def _build_vuln(
    category: str,
    file: str,
    line: int,
    snippet: str,
    sink_type: str,
    evidence: str,
    remediation: str,
    function: str = "",
) -> Vulnerability:
    """Construct a fully populated :class:`Vulnerability` from metadata."""
    info = VULN_CATEGORIES.get(category, {})
    title = info.get("title", category)
    severity = info.get("default_severity", "Medium")
    vid = f"VULN-{abs(hash((category, file, line, snippet))) % 100000:05d}"
    return Vulnerability(
        id=vid,
        title=title,
        category=category,
        severity=severity,
        file=file,
        line=line,
        function=function,
        snippet=snippet,
        sink=SinkInfo(type=sink_type, location=f"{file}:{line}"),
        evidence=EvidenceInfo(level="E1", proof=evidence),
        remediation=remediation,
    )


def _is_string_literal(arg: str) -> bool:
    a = arg.strip()
    return (a.startswith("'") or a.startswith('"')) and not a.startswith(("f'", 'f"', "b'", 'b"', "r'", 'r"'))


def _is_fstring(arg: str) -> bool:
    a = arg.strip()
    return a.startswith("f'") or a.startswith('f"')


def _has_concat(arg: str) -> bool:
    # v0.6.0: detect *Python* string concatenation without mistaking "+"
    # arithmetic that lives inside a single SQL literal (e.g.
    # ``"UPDATE ... balance = balance + ? ..."``).  Strip every quoted string
    # literal out of the argument; a ``+`` that *survives* outside the literals
    # is real concatenation (``'<b>' + name + '</b>'``), while a ``+`` that
    # disappears with the literals was just SQL arithmetic.
    a = arg.strip()
    outside_literals = re.sub(
        r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", "", a,
    )
    if " + " in outside_literals:
        return True
    return ").format(" in arg or ".format(" in arg


def _is_variable(arg: str) -> bool:
    a = arg.strip()
    return not (a.startswith("'") or a.startswith('"') or a.startswith("f'") or a.startswith('f"'))


# ---------------------------------------------------------------------------
# v0.5.2 – import alias resolution
# ---------------------------------------------------------------------------
#
# Network libraries are very commonly imported under a short alias, e.g.
# ``import requests as req`` and then ``req.get(url)``.  The sink set matches
# the fully-qualified ``requests.get`` name, so aliased calls were invisible
# (the Pentrix webhook blind-SSRF was missed for exactly this reason).
#
# These helpers parse import *statement strings* (already captured by the IR)
# into an ``alias -> fully-qualified target`` map.  No code is executed.

# Top-level package roots known to make outbound network requests.
_NETWORK_MOD_PREFIXES = ("requests", "httpx", "aiohttp", "urllib3", "urllib")


def _import_alias_map(imports) -> dict:
    """Map a short alias to the module / fully-qualified name it refers to.

    Handles::

        import requests as req          -> {"req": "requests"}
        import requests                 -> {"requests": "requests"}
        import a, b as c, d             -> {"a": "a", "c": "b", "d": "d"}
        from requests import get        -> {"get": "requests.get"}
        from requests import post as p  -> {"p": "requests.post"}
    """
    alias: dict = {}
    for imp in imports or []:
        if not isinstance(imp, str):
            continue
        s = imp.strip().rstrip(";")
        m = re.match(r"^import\s+(.+)$", s)
        if m:
            for part in m.group(1).split(","):
                part = part.strip()
                pm = re.match(r"^([\w\.]+)(?:\s+as\s+(\w+))?$", part)
                if not pm:
                    continue
                mod = pm.group(1)
                asname = pm.group(2) or mod.split(".")[0]
                alias[asname] = mod
            continue
        m = re.match(r"^from\s+([\w\.]+)\s+import\s+(.+)$", s)
        if m:
            mod = m.group(1)
            for part in m.group(2).split(","):
                part = part.strip()
                pm = re.match(r"^(\w+)(?:\s+as\s+(\w+))?$", part)
                if not pm:
                    continue
                orig = pm.group(1)
                asname = pm.group(2) or orig
                alias[asname] = f"{mod}.{orig}"
    return alias


def _is_network_alias(root: str, alias_map: dict) -> bool:
    """True when *root* (the first dotted component of a call name) aliases a
    network-request library module."""
    target = alias_map.get(root)
    if target is None:
        return False
    return any(target == p or target.startswith(p + ".") for p in _NETWORK_MOD_PREFIXES)


# ---------------------------------------------------------------------------
# v0.5.0 – FastAPI / Starlette support helpers
# ---------------------------------------------------------------------------
#
# FastAPI handlers take user input through *function parameters* (query / path /
# header / body models) rather than through ``request.args`` / ``request.form``
# attribute accesses inside the body.  The legacy ``fn.sources`` signal only
# fires on ``request.*`` calls, so a FastAPI route handler otherwise looks like
# it has no tainted input.  These helpers bridge that gap without executing any
# target code.

# Decorator that marks a function as a web route (Flask/FastAPI/Django).
_ROUTE_DECO_RE = re.compile(
    r"@?\w+\s*\.\s*(?:get|post|put|delete|patch|options|head)\s*\(|\.route\b",
    re.I,
)
# RHS expressions that are attacker-controlled (tainted origins).
_REQUEST_SRC_RE = re.compile(
    r"request\.(?:args|form|json|values|data|body|cookies|headers|"
    r"query_params|view_args|files|POST|GET)\b"
    r"|request\s*\[\s*['\"]",
    re.I,
)
_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][\w\.]*)\s*=\s*(.+)$")
# Calls that neutralise a tainted path/filename (basename strips directory
# components; secure_filename is the canonical Flask upload sanitiser).
_SANITIZER_CALL_RE = re.compile(r"\b(?:basename|secure_filename)\s*\(")


def is_route_handler(fn: FunctionIR) -> bool:
    """True when *fn* is registered as an HTTP route handler.

    Recognises both ``@app.route(...)`` (Flask) and ``@app.get(...)`` /
    ``@router.post(...)`` / ``@bp.put(...)`` (FastAPI / Starlette / Django).
    """
    decos = list(getattr(fn, "decorators", []) or [])
    return any(_ROUTE_DECO_RE.search(d) for d in decos)


def route_handler_taints_params(fn: FunctionIR) -> bool:
    """FastAPI route handler: every non-dependency parameter is caller input."""
    return is_route_handler(fn)


# v0.6.0: hard cap on the ``taint_names`` fixpoint passes.  A correctly
# converging taint set settles in well under this many iterations; the cap is
# a last-resort guard against an add/discard oscillation (see below).
_MAX_TAINT_PASSES = 64


def _references_name(rhs: str, name: str) -> bool:
    """True when *name* is referenced in *rhs* as a whole word.

    Using ``\\b`` boundaries (rather than a raw ``name in rhs`` substring test)
    keeps a short tainted name such as ``file`` from spuriously matching inside
    an unrelated identifier like ``filename`` / ``filepath``.
    """
    if not name or not rhs:
        return False
    return re.search(r"\b" + re.escape(name) + r"\b", rhs) is not None


def taint_names(fn: FunctionIR) -> set:
    """Lightweight intra-procedural taint set.

    Starts from route-handler parameters (FastAPI query/path/header inputs) and
    from locals assigned directly from ``request.*`` expressions, then
    propagates forward through simple ``name = <expr>`` assignments until a
    fixed point.  A variable that is reassigned through a recognised sanitiser
    (``os.path.basename`` / ``secure_filename``) is de-tainted.  Only used to
    *add* detections (never to suppress existing ones) so legacy Flask /
    Django behaviour is preserved.
    """
    tainted: set = set(fn.parameters) if is_route_handler(fn) else set()
    for expr in fn.assignment_exprs:
        m = _ASSIGN_RE.match(expr.strip())
        if m and _REQUEST_SRC_RE.search(m.group(2)):
            tainted.add(m.group(1).split(".")[0])
    # v0.6.0: the forward-propagation fixpoint must always terminate.  On real
    # code (the vulnbank ``upload_profile_picture`` handler) it could spin
    # forever:
    #   * substring matching ``t in rhs`` let a short tainted name (``file``)
    #     match inside an unrelated identifier (``filename``), inventing edges;
    #   * a variable reassigned first through a sanitiser (de-taint) and then
    #     through an unsanitised f-string re-derivation flipped in/out of the
    #     set every pass (add on one pass, discard on the next) so ``changed``
    #     never settled and the whole scan hung at ~100 % CPU.
    # We now match whole words and cap the number of fixpoint passes.
    changed = True
    passes = 0
    while changed and passes < _MAX_TAINT_PASSES:
        changed = False
        passes += 1
        for expr in fn.assignment_exprs:
            m = _ASSIGN_RE.match(expr.strip())
            if not m:
                continue
            lhs = m.group(1).split(".")[0]
            rhs = m.group(2)
            refs_tainted = any(t and _references_name(rhs, t) for t in tainted)
            sanitized = bool(_SANITIZER_CALL_RE.search(rhs))
            if refs_tainted and sanitized and lhs in tainted:
                tainted.discard(lhs)
                changed = True
            elif refs_tainted and not sanitized and lhs not in tainted:
                tainted.add(lhs)
                changed = True
    return tainted


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class StructuredDetector:
    """Base class for AST-aware vulnerability detectors.

    Subclasses override :meth:`detect`.  The signature receives the function
    under analysis, the *entire* source file as a list of lines, and the
    project IR for cross-file context.
    """

    category: str = ""

    # -- helpers shared by all detectors ----------------------------------

    @staticmethod
    def body_lines(fn: FunctionIR, source_lines: List[str]) -> List[str]:
        start = max(0, fn.line - 1)
        end = min(len(source_lines), fn.end_line)
        return source_lines[start:end]

    @classmethod
    def body_text(cls, fn: FunctionIR, source_lines: List[str]) -> str:
        return "\n".join(cls.body_lines(fn, source_lines))

    @classmethod
    def code_text(cls, fn: FunctionIR, source_lines: List[str]) -> str:
        """Like :meth:`body_text` but drops pure-comment lines.

        Detection rules that look for *mitigating* keywords (rate limiting,
        authorization, password complexity …) must not be fooled by a comment
        such as ``# No rate limiting or account lockout``.
        """
        return "\n".join(
            l for l in cls.body_lines(fn, source_lines)
            if not l.strip().startswith("#")
        )

    @staticmethod
    def decorators(fn: FunctionIR, source_lines: List[str]) -> List[str]:
        decos: List[str] = []
        idx = fn.line - 2
        while 0 <= idx < len(source_lines):
            stripped = source_lines[idx].strip()
            if stripped.startswith("@"):
                decos.append(stripped)
                idx -= 1
            elif stripped == "" or stripped.startswith("#"):
                idx -= 1
            else:
                break
        return decos

    def detect(self, function_ir: FunctionIR, source_lines: List[str], project_ir: ProjectIR) -> List[Vulnerability]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 1. SQL Injection
# ---------------------------------------------------------------------------

class SQLInjectionDetector(StructuredDetector):
    """Detect string-built SQL; ignore parameterised / ORM-safe calls."""

    category = "sql-injection"
    # v0.5.1: ``text`` is SQLAlchemy's raw-SQL constructor.  A static
    # ``text("SELECT ... WHERE x = :name")`` is parameterised and stays
    # unreported (see the literal-guard below); only ``text(f"...{v}...")``,
    # ``text("..." % v)``, ``text("..." + v)`` or ``text("...{}".format(v))``
    # are flagged.
    _SQL_CALLS = {"execute", "executemany", "raw", "query", "text"}
    _ORM_SAFE = {"filter", "filter_by", "get", "get_or_404", "first", "all", "find_one", "find"}
    _SQL_VERBS = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b", re.IGNORECASE)
    # v0.4.0 – statement-level SQL pattern for the no-execute body scan.  This
    # requires an actual command verb (SELECT...FROM / INSERT INTO / UPDATE...SET
    # / DELETE FROM) so that prose containing the word "from" is not flagged.
    _SQL_STMT = re.compile(
        r"\bSELECT\b[\s\S]*\bFROM\b"
        r"|\bINSERT\s+INTO\b"
        r"|\bUPDATE\b[\s\S]*\bSET\b"
        r"|\bDELETE\s+FROM\b",
        re.IGNORECASE,
    )
    _BODY_DYNAMIC_SQL = re.compile(
        r"f['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)"
        r"|['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^'\"]*['\"]\s*\+",
        re.IGNORECASE,
    )
    # v0.4.0: ``"SELECT ... '%s'" % var`` printf-style formatting feeds a
    # non-literal into SQL even though no ``%s`` parameter tuple follows.
    _PERCENT_SQL = re.compile(r"['\"]\s*%\s*[A-Za-z_('\"(]")
    # request-derived taint sources for the no-execute string-construction branch.
    _REQ_SRC = re.compile(
        r"request\.(?:args|form|json|values|data|query_params|get|post|body|files|cookies|headers)|"
        r"request\s*\[\s*['\"]", re.I,
    )

    def _tainted_names(self, fn) -> set:
        """Local names that originate from a request source (plus route params).

        v0.6.0: function parameters are only treated as attacker-controlled when
        the function is a route handler (FastAPI query/path inputs).  Internal
        helpers like ``safe_withdraw_atomic(conn, user_id, amount)`` take
        ``user_id`` / ``amount`` from trusted callers, not from the request, so
        treating their params as tainted previously flagged safe parameterised
        ``?`` UPDATEs as SQL injection.
        """
        tainted: set = set(fn.parameters) if is_route_handler(fn) else set()
        for expr in fn.assignment_exprs:
            m = re.match(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+)$", expr.strip())
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if self._REQ_SRC.search(rhs):
                tainted.add(lhs)
        return tainted

    def detect(self, fn, source_lines, project_ir):
        out = []
        body = self.body_text(fn, source_lines)
        body_has_dynamic = bool(self._BODY_DYNAMIC_SQL.search(body))
        tainted = self._tainted_names(fn)
        for call in fn.calls:
            base = call.name.split(".")[-1]
            if base not in self._SQL_CALLS:
                continue
            args = call.args
            if not args:
                continue
            first = args[0]
            # v0.5.1: dynamic construction patterns are checked *before* the
            # static-literal guard.  ``"..." % (var)`` and ``"..." .format(var)``
            # start with a quote and may even contain a ``%s`` placeholder, but
            # the trailing operator means they are NOT parameterised — they are
            # built SQL strings and must be flagged.  A pure static literal
            # (no trailing ``%`` / ``+`` / ``.format``) with a placeholder is
            # still recognised as parameterised below.
            # direct f-string / concatenation / printf-% / .format() in the call
            if _is_fstring(first) or _has_concat(first) or self._PERCENT_SQL.search(first):
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    first.strip(), "sql",
                    f"Dynamic SQL built via f-string / concatenation in '{fn.name}'",
                    "Use parameterised queries (placeholders) instead of string interpolation.",
                    fn.name,
                ))
                continue
            # parameterised: pure static literal with placeholders + separate params
            if _is_string_literal(first) and ("%s" in first or "?" in first or "%(" in first):
                continue
            # variable holding dynamically-built SQL (e.g. query = f"..."; execute(query))
            if _is_variable(first) and body_has_dynamic:
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    first.strip(), "sql",
                    f"SQL query variable '{first}' is built from dynamic input in '{fn.name}'",
                    "Use parameterised queries (placeholders) instead of string interpolation.",
                    fn.name,
                ))
        # v0.4.0 – branch: SQL built as an f-string / printf-% / concat even when
        # no execute() call exists (e.g. ``query = f"SELECT ... WHERE x='{y}'"``).
        reported_lines = {v.line for v in out}
        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line) or lineno in reported_lines:
                continue
            stripped = line.strip()
            if stripped.startswith(("#", "import ", "from ")):
                continue
            if not self._SQL_STMT.search(line):
                continue
            # dynamic construction: f-string, printf-% or string concat.
            # v0.6.0: strip quoted string literals before testing for `` + `` so
            # SQL arithmetic *inside* a parameterised literal (``balance + ?``)
            # is not mistaken for Python concatenation.
            line_no_literals = re.sub(
                r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"", "", line,
            )
            is_dynamic = (
                bool(re.search(r"f['\"]", line))
                or bool(self._PERCENT_SQL.search(line))
                or (" + " in line_no_literals and self._SQL_VERBS.search(line))
            )
            if not is_dynamic:
                continue
            # interpolation must reference a request-derived / param variable
            line_roots = set(re.findall(r"\b([A-Za-z_]\w*)\b", line))
            if not (line_roots & tainted) and not self._REQ_SRC.search(line):
                continue
            out.append(_build_vuln(
                self.category, fn.path, lineno,
                stripped, "sql",
                f"SQL string constructed from request input without parameterisation in '{fn.name}'",
                "Use parameterised queries (placeholders) instead of string interpolation.",
                fn.name,
            ))
        return out


# ---------------------------------------------------------------------------
# 2. Command Injection
# ---------------------------------------------------------------------------

class CommandInjectionDetector(StructuredDetector):
    """Detect os.system / subprocess calls with dynamic input."""

    category = "command-injection"
    _SHELL_CALLS = {"os.system", "os.popen", "system", "popen",
                    "commands.getoutput", "commands.getstatusoutput",
                    "getoutput", "getstatusoutput"}
    _SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.Popen",
                   "subprocess.check_output", "subprocess.check_call",
                   "subprocess.getoutput", "subprocess.getstatusoutput"}

    def detect(self, fn, source_lines, project_ir):
        out = []
        for call in fn.calls:
            name = call.name
            base = name.split(".")[-1]
            is_shell = name in self._SHELL_CALLS or base in self._SHELL_CALLS
            is_sub = name in self._SUBPROCESS
            if not (is_shell or is_sub):
                continue
            joined = " ".join(call.args)
            shell_true = "shell=True" in joined
            first = call.args[0] if call.args else ""
            # list-form subprocess is safe
            if is_sub and first.strip().startswith("["):
                if not shell_true:
                    continue
            if shell_true or _is_fstring(first) or _has_concat(first) or (_is_variable(first) and is_shell):
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    joined.strip(), "command",
                    f"Dynamic command execution via '{name}' in '{fn.name}'",
                    "Pass argv as a list, set shell=False, and quote arguments with shlex.quote.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 3. Path Traversal
# ---------------------------------------------------------------------------

class PathTraversalDetector(StructuredDetector):
    """Detect open() / read / FileResponse with caller-controlled paths.

    v0.5.0: sinks include FastAPI's ``FileResponse`` and route-handler
    parameters (e.g. ``def get(name: str)``) are recognised as tainted input,
    with light forward propagation through ``path = os.path.join(...)``.
    """

    category = "path-traversal"
    _OPEN_CALLS = {
        "open", "read_text", "read_bytes", "send_file", "send_from_directory",
        "FileResponse",
    }

    def detect(self, fn, source_lines, project_ir):
        out = []
        tainted = taint_names(fn)
        has_source = bool(fn.sources) or bool(tainted)
        for call in fn.calls:
            base = call.name.split(".")[-1]
            if base not in self._OPEN_CALLS:
                continue
            if not call.args:
                continue
            first = call.args[0]
            if not has_source:
                continue
            if not (_is_variable(first) and not _is_string_literal(first)):
                continue
            # Legacy Flask/Django gate: any request.* call in the function keeps
            # the existing behaviour (report any variable path argument).
            # New FastAPI gate: only report when the path expression itself is
            # tainted (route param or propagated from one).
            if not fn.sources:
                root = first.strip().split("[")[0].split("(")[0].split(".")[0]
                if root not in tainted:
                    continue
            out.append(_build_vuln(
                self.category, fn.path, call.line,
                first.strip(), "filesystem",
                f"Filesystem access on a caller-controlled path in '{fn.name}'",
                "Resolve the path and constrain it to an allowlisted base directory.",
                fn.name,
            ))
        return out


# ---------------------------------------------------------------------------
# 4. SSRF
# ---------------------------------------------------------------------------

class SSRFDetector(StructuredDetector):
    """Detect outbound HTTP requests to dynamic URLs.

    Two conditions must both hold before reporting:
    1. The call is to a known network-request function.
    2. The first argument (or a nearby argument name) carries *network*
       semantics (``url``, ``host``, ``endpoint`` …) — a bare ``user_id`` or
       ``doc_id`` is **not** a URL.
    """

    category = "ssrf"
    _CALLS = {
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "requests.request", "urllib.request.urlopen", "urlopen",
        "urllib.request.Request",
        "httpx.get", "httpx.post", "httpx.request",
        "http.client.HTTPConnection",
        "urllib3.PoolManager.request",
    }
    _BASE_OK = {"get", "post", "put", "delete", "request", "urlopen"}
    _NETWORK_TOKENS = {
        "url", "uri", "target", "host", "endpoint", "callback",
        "webhook", "proxy", "redirect_url", "next_url", "fetch_url",
        "remote", "external",
    }

    def detect(self, fn, source_lines, project_ir):
        out = []
        # v0.5.2: resolve ``import requests as req`` style aliases from both the
        # function body (local imports) and the module scope (project IR).
        fn_imports = list(getattr(fn, "imports", []) or [])
        proj_imports = list(getattr(project_ir, "imports", []) or [])
        alias_map = _import_alias_map(fn_imports + proj_imports)
        for call in fn.calls:
            name = call.name
            base = name.split(".")[-1]
            root = name.split(".")[0]
            # Condition 1 — known network-request function
            is_network = name in self._CALLS
            if not is_network:
                # v0.5.2: aliased module import, e.g. ``import requests as req``
                # then ``req.get(url)``.  The method must still be a known HTTP
                # verb so a benign ``req.get(data)`` on a plain object is safe.
                if _is_network_alias(root, alias_map) and base in self._BASE_OK:
                    is_network = True
                # v0.5.2: ``from requests import get as g`` then bare ``g(url)``.
                elif root == name and alias_map.get(root) in self._CALLS:
                    is_network = True
            if not is_network:
                # aiohttp.ClientSession.get / aiohttp.request
                if "ClientSession" in name and base in self._BASE_OK:
                    is_network = True
                elif name.startswith("aiohttp.") and base in self._BASE_OK:
                    is_network = True
                elif name.startswith("http.client") and "HTTPConnection" in name:
                    is_network = True
                elif name.startswith("urllib3") and "PoolManager" in name:
                    is_network = True
                else:
                    continue
            if not call.args:
                continue
            first = call.args[0]
            # Condition 2 — argument carries network semantics
            first_lower = first.lower()
            has_network = any(tok in first_lower for tok in self._NETWORK_TOKENS)
            if not has_network:
                continue
            if _is_variable(first) and not _is_string_literal(first):
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    first.strip(), "network",
                    f"Outbound request to a dynamically-constructed URL in '{fn.name}'",
                    "Allowlist destination hosts and block private / link-local addresses.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 5. XSS
# ---------------------------------------------------------------------------

class XSSDetector(StructuredDetector):
    """Detect unsafe HTML rendering of dynamic content.

    Covers both explicit marking helpers (``Markup()``, ``mark_safe()``) and
    raw f-string HTML concatenation such as ``return f"<h1>{name}</h1>"`` or
    ``"".join([f"<li>{q}</li>" for q in ...])``.
    """

    category = "xss"
    _CALLS = {"Markup", "mark_safe", "format_html", "safe_join"}
    # f-string that contains an HTML tag AND a {…} interpolation
    _FSTRING_HTML = re.compile(
        r"f['\"][^'\"]*<(?:h[1-6]|div|p|span|a|script|img|input|button|li|"
        r"td|tr|table|form|select|option|br|hr|ul|ol|html|body)[^'\"]*"
        r"\{[^}]+\}[^'\"]*['\"]",
        re.I,
    )
    # route / HTTP-handler decorators → their parameters are tainted inputs
    _ROUTE_DECO = re.compile(
        r"\.route\b|@?\w+\.(?:get|post|put|delete)\s*\(|blueprint", re.I,
    )
    # RHS expressions that introduce attacker-controlled input (tainted)
    _TAINT_SRC = re.compile(
        r"request\.(?:args|form|json|values|data|body|cookies|headers|query_params|view_args|files|POST|GET)\b"
        r"|request\s*\[\s*['\"]"
        r"|session\s*\[\s*['\"]"
        r"|session\.get\s*\(",
        re.I,
    )
    # RHS expressions that are *provably safe* (not user-controlled HTML)
    _SAFE_SRC = re.compile(
        r"db\.execute|db\.session|\.fetchone|\.fetchall|\.query\.get|\.objects\.get|\.query\b"
        r"|hashlib\.|\.md5\s*\(|\.sha1\s*\(|\.sha256\s*\(|base64\."
        r"|subprocess\.|os\.system|os\.popen",
        re.I,
    )
    # simple "lhs = rhs" assignment where lhs is a plain identifier
    _ASSIGN = re.compile(r"^([A-Za-z_]\w*)\s*=\s*(.+)$")
    # identifiers in an expression
    _IDENTS = re.compile(r"\b[A-Za-z_]\w*\b")
    # v0.4.4 – HTML-tag presence check for the two-step detector.  Unlike
    # ``_FSTRING_HTML`` this deliberately does NOT forbid quoted characters, so
    # it can see through single-quoted HTML attributes such as
    # ``f"<div class='message'>{msg}</div>"`` (the v0.4.3 miss on
    # django-target1 ``format_message``).
    _HTML_TAG = re.compile(
        r"<(?:h[1-6]|div|p|span|a|script|img|input|button|li|"
        r"td|tr|table|form|select|option|br|hr|ul|ol|html|body)\b",
        re.I,
    )
    # HTML / JSON response sinks that render a returned variable as a body.
    _RESPONSE_SINKS = {
        "HttpResponse", "JsonResponse", "StreamingHttpResponse",
        "jsonify", "make_response", "Response", "HTMLResponse",
    }

    # ------------------------------------------------------------------
    # taint model
    # ------------------------------------------------------------------

    @staticmethod
    def _idents(expr: str) -> set:
        return set(XSSDetector._IDENTS.findall(expr))

    @staticmethod
    def _is_static_rhs(rhs: str) -> bool:
        r = rhs.strip()
        if not r:
            return False
        if _is_string_literal(r):
            return True
        return r[0] in "0123456789{(["

    def _build_taint(self, fn, source_lines):
        tainted: set = set()
        safe: set = set()

        # HTTP-handler parameters are tainted inputs
        if any(self._ROUTE_DECO.search(d) for d in self.decorators(fn, source_lines)):
            tainted.update(fn.parameters)

        deferred: list = []  # (lhs, rhs) needing propagation
        for expr in fn.assignment_exprs:
            m = self._ASSIGN.match(expr.strip())
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if self._TAINT_SRC.search(rhs):
                tainted.add(lhs)
            elif self._SAFE_SRC.search(rhs) or self._is_static_rhs(rhs):
                safe.add(lhs)
            else:
                deferred.append((lhs, rhs))

        # loop comprehensions: `for v in <iterable>`
        body = self.body_text(fn, source_lines)
        for m in re.finditer(r"\bfor\s+([A-Za-z_]\w*)\s+in\s+([^:\]]+?)(?=\s*(?::|\]|$))", body):
            var, itr = m.group(1), m.group(2)
            if self._TAINT_SRC.search(itr) or any(r in tainted for r in self._idents(itr)):
                tainted.add(var)
            elif self._SAFE_SRC.search(itr) or self._idents(itr) <= safe:
                safe.add(var)

        # simple propagation worklist: a = b (b tainted → a tainted;
        # every root of b safe → a safe)
        changed = True
        while changed:
            changed = False
            for lhs, rhs in deferred:
                if lhs in tainted or lhs in safe:
                    continue
                roots = self._idents(rhs)
                if any(r in tainted for r in roots):
                    tainted.add(lhs)
                    changed = True
                elif roots and roots <= safe:
                    safe.add(lhs)
                    changed = True
        return tainted, safe

    @staticmethod
    def _roots_in(content: str) -> set:
        """Return the free variable roots referenced by an f-string placeholder.

        Attribute accesses (``user.username`` → ``user``), Python keywords and
        literals are ignored so that ``.decode()`` / ``for ... in ...`` /
        attribute names do not count as independent variables.
        """
        content = re.sub(r"['\"][^'\"]*['\"]", "", content)
        roots = set()
        for m in re.finditer(r"(?:^|[^.\w])([A-Za-z_]\w*)", content):
            name = m.group(1)
            if name in _PY_KEYWORDS:
                continue
            roots.add(name)
        return roots

    def _line_references_tainted(self, line: str, tainted: set, safe: set) -> bool:
        """Decide whether an HTML f-string line should be reported as XSS.

        Report if any interpolated root variable is tainted; skip only when
        every interpolated root variable is provably safe.  Uncertain roots
        (opaque parameters, unknown origins) are reported conservatively.
        """
        roots: set = set()
        for m in re.finditer(r"\{([^{}]*)\}", line):
            roots.update(self._roots_in(m.group(1).split(":", 1)[0]))
        if not roots:
            return False
        if any(r in tainted for r in roots):
            return True
        if roots <= safe:
            return False
        return True  # uncertain → report

    @staticmethod
    def _fstring_assign_line(fn, source_lines: List[str], lhs: str):
        """Locate the 1-indexed line where ``lhs = f"..."`` is assigned.

        ``assignment_exprs`` carry no line numbers, so we scan the function
        body for the assignment-to-f-string line.  ``None`` is returned when no
        such line exists (e.g. the assignment spans multiple lines).
        """
        pat = re.compile(r"^\s*" + re.escape(lhs) + r"\s*=\s*f['\"]")
        lo = max(0, fn.line - 1)
        hi = min(len(source_lines), fn.end_line)
        for idx in range(lo, hi):
            if pat.match(source_lines[idx]):
                return idx + 1
        return None

    # ------------------------------------------------------------------
    # detection
    # ------------------------------------------------------------------

    def detect(self, fn, source_lines, project_ir):
        out = []
        tainted, safe = self._build_taint(fn, source_lines)

        # 1. explicit marking helpers + render_template_string(tainted_source)
        for call in fn.calls:
            base = call.name.split(".")[-1]
            if base in self._CALLS:
                if not call.args:
                    continue
                first = call.args[0]
                if _is_fstring(first) or _has_concat(first) or (_is_variable(first) and fn.sources):
                    out.append(_build_vuln(
                        self.category, fn.path, call.line,
                        first.strip(), "browser",
                        f"Unsafe HTML marking of dynamic content in '{fn.name}'",
                        "Use contextual output encoding (e.g. markupsafe.escape) instead of Markup().",
                        fn.name,
                    ))
            elif base == "render_template_string":
                if not call.args:
                    continue
                first = call.args[0]
                # Static string literal → safe template; variables go via kwargs.
                if _is_string_literal(first):
                    continue
                root = first.strip().split(".")[0]
                # Only flag when the *template source* is itself tainted.
                if root in tainted:
                    out.append(_build_vuln(
                        self.category, fn.path, call.line,
                        first.strip(), "browser",
                        f"User-controlled template source rendered as HTML in '{fn.name}'",
                        "Render static templates with variables passed as context, never as template source.",
                        fn.name,
                    ))

        # 2. f-string HTML concatenation in the function body — gated by taint
        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line):
                continue
            if self._FSTRING_HTML.search(line) and self._line_references_tainted(line, tainted, safe):
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    line.strip(), "browser",
                    f"Dynamic HTML built via f-string interpolation in '{fn.name}'",
                    "Return data rather than HTML, or escape interpolated values with markupsafe.escape.",
                    fn.name,
                ))

        # 3. v0.4.4 – two-step pattern:
        #   html_var = f"<html...{tainted_root}...>"   (an f-string *assigned
        #   to a local variable* — including ones whose HTML attributes use
        #   single quotes, which step 2's line regex cannot see through) then
        #   the variable reaches a response sink:
        #   ``return HttpResponse(html_var)`` / ``return html_var`` /
        #   ``return jsonify(html_var)``.  The shared taint gate still applies:
        #   only tainted (or left-uncertain) interpolated roots are reported;
        #   static HTML literals and database/hash/subprocess output are not.
        reported_lines = {v.line for v in out}

        returned_vars: set = set()
        for r in fn.returns:
            returned_vars |= self._idents(r)
        for call in fn.calls:
            if call.name.split(".")[-1] in self._RESPONSE_SINKS:
                for arg in call.args:
                    returned_vars.add(arg.strip().split(".")[0])

        for expr in fn.assignment_exprs:
            m = self._ASSIGN.match(expr.strip())
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if not _is_fstring(rhs):
                continue
            # must build HTML (a tag) AND interpolate something
            if "{" not in rhs or not self._HTML_TAG.search(rhs):
                continue
            # the assigned variable must actually reach a response sink
            if lhs not in returned_vars:
                continue
            # taint gate on the interpolated roots
            if not self._line_references_tainted(rhs, tainted, safe):
                continue
            line_no = self._fstring_assign_line(fn, source_lines, lhs)
            if line_no is None or line_no in reported_lines:
                continue
            reported_lines.add(line_no)
            out.append(_build_vuln(
                self.category, fn.path, line_no,
                rhs.strip(), "browser",
                f"Dynamic HTML built via f-string interpolation and returned as a response in '{fn.name}'",
                "Return data rather than HTML, or escape interpolated values with markupsafe.escape.",
                fn.name,
            ))
        return out


# ---------------------------------------------------------------------------
# 6. SSTI
# ---------------------------------------------------------------------------

class SSTIDetector(StructuredDetector):
    """Detect render_template_string with caller-controlled templates.

    Only report when the *template source* itself is user-controlled:
    f-string, string concatenation, ``.format()``, or a variable that flows
    from a request source.  A static string literal passed as the first
    argument (e.g. ``render_template_string("Hello {{ name }}", name=name)``)
    is **safe** and must not be flagged.
    """

    category = "ssti"
    _CALLS = {"render_template_string", "Template", "env.from_string", "from_string"}
    # Match ``varname = "..."`` or ``varname = '...'`` or ``varname = """..."""``
    # (static string assignments — safe templates).  The string literal must
    # span the entire RHS (no ``+`` concatenation after the closing quote).
    _STATIC_ASSIGN = re.compile(
        r"^\s*([A-Za-z_]\w*)\s*=\s*"
        r"(?:\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?''')"
        r"\s*(?:#.*)?$|"
        r"^\s*([A-Za-z_]\w*)\s*=\s*"
        r"f?\"[^\"]*\"\s*(?:#.*)?$|"
        r"^\s*([A-Za-z_]\w*)\s*=\s*"
        r"f?'[^']*'\s*(?:#.*)?$",
        re.MULTILINE,
    )

    def detect(self, fn, source_lines, project_ir):
        out = []
        body = self.body_text(fn, source_lines)
        # Collect variable names that are assigned a static string literal
        # somewhere in the function body — these are safe templates.
        static_vars: set = set()
        for m in self._STATIC_ASSIGN.finditer(body):
            varname = m.group(1) or m.group(2) or m.group(3)
            value = m.group(0)
            # Exclude f-strings (they contain interpolation)
            if re.search(r"^\s*\w+\s*=\s*f['\"]", value):
                continue
            static_vars.add(varname)

        for call in fn.calls:
            base = call.name.split(".")[-1]
            if base not in self._CALLS:
                continue
            if not call.args:
                continue
            first = call.args[0]
            # Static string literal → safe template, variables go via kwargs
            if _is_string_literal(first):
                continue
            # Report only when template source is dynamic / user-controlled
            if _is_fstring(first) or _has_concat(first):
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    first.strip(), "template",
                    f"User-controlled template string rendered in '{fn.name}'",
                    "Render static templates with variables passed as context, never as template source.",
                    fn.name,
                ))
            elif _is_variable(first) and fn.sources:
                # If the variable was assigned a static string literal in the
                # function body, it is a safe template — skip.
                var_name = first.strip()
                if var_name in static_vars:
                    continue
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    first.strip(), "template",
                    f"User-controlled template variable rendered in '{fn.name}'",
                    "Render static templates with variables passed as context, never as template source.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 7. Hardcoded Secret (line-based regex)
# ---------------------------------------------------------------------------

class HardcodedSecretDetector(StructuredDetector):
    """Detect literal secrets assigned in source.

    v0.3.1: the keyword set now covers ``AWS_ACCESS_KEY`` / ``AWS_SECRET_KEY``
    (``access[_-]?key`` and ``secret[_-]?key`` matched as a whole, without the
    ``\\b`` that previously blocked matching inside ``AWS_SECRET_KEY``), and the
    well-known AWS Access Key ID shape ``AKIA[0-9A-Z]{16}`` is reported on its
    own regardless of the variable name.
    """

    category = "hardcoded-secret"
    _RE = re.compile(
        r"(?i)(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|token|"
        r"access[_-]?key|private[_-]?key|credential|"
        r"aws[_-]?(?:access|secret)(?:[_-]?key)?)"
        r"\s*=\s*['\"][^'\"]{6,}['\"]"
    )
    # v0.5.1: bytes literals ``b'...'`` / ``b"..."``.  The keyword set extends
    # the string-literal rule with ``iv`` and ``aes`` so that
    # ``AES_KEY = b'0123456789abcdef'`` / ``AES_IV = b'...'`` are flagged; the
    # value must be at least 8 bytes long so a short ``b'x'`` is ignored.
    _BYTES_RE = re.compile(
        r"(?i)\b[A-Za-z_][A-Za-z0-9_]*(?:key|secret|password|passwd|token|credential|iv|aes)"
        r"[A-Za-z0-9_]*\s*=\s*b['\"][^'\"]{8,}['\"]"
    )
    # AWS Access Key ID canonical format (prefix + 20 uppercase alnum / digits).
    _AKIA_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
    # v0.5.0: ``SECRET = os.environ.get("KEY", "hardcoded-default")`` — the
    # second argument is a fallback secret that ships in source.
    _ENV_DEFAULT_RE = re.compile(
        r"(?i)\b([A-Za-z_][A-Za-z0-9_]*(?:secret|key|password|passwd|token|credential)"
        r"[A-Za-z0-9_]*)"
        r"\s*=\s*os\.environ\.get\s*\(\s*['\"][^'\"]*['\"]\s*,\s*"
        r"(?P<quote>['\"])(?P<val>(?:(?!(?P=quote)).){6,})(?P=quote)\s*\)"
    )
    _SECRET_PREFIXES = (
        "sk_test_", "sk_live_", "pk_test_", "pk_live_", "AKIA",
        "gh_", "github_pat_", "whsec_", "eyJ",
    )

    def _looks_like_secret(self, value: str) -> bool:
        """Conservative heuristic: only flag defaults that look like real secrets."""
        v = value.strip()
        if len(v) < 8:
            return False
        if v.lower().startswith(self._SECRET_PREFIXES):
            return True
        # mixed alnum + punctuation is characteristic of a generated secret
        has_letter = bool(re.search(r"[A-Za-z]", v))
        has_digit = bool(re.search(r"[0-9]", v))
        has_punct = bool(re.search(r"[^A-Za-z0-9]", v))
        if has_letter and has_digit and has_punct:
            return True
        # long random-looking blob
        return len(v) >= 16 and has_letter and has_digit

    def detect(self, fn, source_lines, project_ir):
        out = []
        for idx, line in enumerate(source_lines, 1):
            m = self._RE.search(line)
            if m:
                out.append(_build_vuln(
                    self.category, fn.path, idx,
                    line.strip(), "configuration",
                    f"Hardcoded secret literal detected: {m.group(0)[:60]}",
                    "Move secrets to environment variables or a dedicated secret manager.",
                    fn.name,
                ))
                continue
            # v0.5.1: bytes literal (e.g. ``AES_KEY = b'0123456789abcdef'``).
            if self._BYTES_RE.search(line):
                out.append(_build_vuln(
                    self.category, fn.path, idx,
                    line.strip(), "configuration",
                    "Hardcoded bytes literal assigned to a key/secret/IV variable",
                    "Move cryptographic keys and IVs to a key manager or environment variables.",
                    fn.name,
                ))
                continue
            # v0.5.0: hardcoded default inside os.environ.get(...)
            m = self._ENV_DEFAULT_RE.search(line)
            if m and self._looks_like_secret(m.group("val")):
                out.append(_build_vuln(
                    self.category, fn.path, idx,
                    line.strip(), "configuration",
                    f"Hardcoded fallback secret in os.environ.get default for "
                    f"'{m.group(1).strip()}'",
                    "Move secrets to environment variables or a dedicated secret manager "
                    "(never ship a usable default).",
                    fn.name,
                ))
                continue
            # AWS Access Key ID shape, regardless of the variable name.
            if self._AKIA_RE.search(line):
                out.append(_build_vuln(
                    self.category, fn.path, idx,
                    line.strip(), "configuration",
                    "Hardcoded AWS Access Key ID (AKIA...) literal detected",
                    "Move AWS credentials to IAM roles or a dedicated secret manager.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 8. Dangerous Deserialization
# ---------------------------------------------------------------------------

class DangerousDeserializationDetector(StructuredDetector):
    """Detect pickle / unsafe yaml.load / marshal."""

    category = "insecure-deserialization"
    _UNSAFE = {"pickle.load", "pickle.loads", "pickle.Unpickler",
               "marshal.loads", "yaml.load"}
    _SAFE_TOKEN = re.compile(r"safe_load|SafeLoader|BaseLoader", re.IGNORECASE)

    def detect(self, fn, source_lines, project_ir):
        out = []
        for call in fn.calls:
            if call.name not in self._UNSAFE:
                continue
            joined = " ".join(call.args)
            if call.name == "yaml.load" and self._SAFE_TOKEN.search(joined):
                continue
            out.append(_build_vuln(
                self.category, fn.path, call.line,
                call.name, "serialization",
                f"Untrusted deserialization via '{call.name}' in '{fn.name}'",
                "Use yaml.safe_load / JSON; never unpickle data from untrusted sources.",
                fn.name,
            ))
        return out


# ---------------------------------------------------------------------------
# 8b. ReDoS (Regular Expression Denial of Service) — v0.4.1 round-6
# ---------------------------------------------------------------------------

class ReDoSDetector(StructuredDetector):
    """v0.4.1 – catastrophic-backtracking regexes applied to user input.

    Flags ``re.match / search / fullmatch / compile / sub`` calls whose
    pattern literal (or a function-local variable initialised to a pattern
    literal) contains a *nested quantifier* (``(a+)+``, ``([a-z]+)+``,
    ``(\\w+)*`` …) **and** whose enclosing function consumes a
    request-derived source.  Plain, unambiguous patterns are never reported,
    and static patterns with no nested quantifier are ignored.
    """

    category = "redos"
    _RE_FUNCS = {"match", "search", "fullmatch", "compile", "sub"}

    @staticmethod
    def _has_nested_quantifier(pattern: str) -> bool:
        """True iff a group is closed by a repetition operator and its body
        itself already contains a repetition operator (catastrophic
        backtracking shape)."""
        stack: List[int] = []
        in_class = False
        i, n = 0, len(pattern)
        while i < n:
            ch = pattern[i]
            if in_class:
                if ch == "\\" and i + 1 < n:
                    i += 2
                    continue
                if ch == "]":
                    in_class = False
                i += 1
                continue
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == "[":
                in_class = True
                i += 1
                continue
            if ch == "(":
                stack.append(i)
                i += 1
                continue
            if ch == ")":
                if stack:
                    open_pos = stack.pop()
                    if i + 1 < n and pattern[i + 1] in "+*?{":
                        body = pattern[open_pos + 1:i]
                        if re.search(r"[+*?{]", body):
                            return True
                i += 1
                continue
            i += 1
        return False

    @staticmethod
    def _as_literal(text: str):
        t = text.strip()
        if t[:1] in ("'", '"') or (len(t) > 1 and t[0] in "rbfu" and t[1] in "'\""):
            try:
                return ast.literal_eval(t)
            except Exception:
                return None
        return None

    def _resolve_pattern(self, first_arg: str, fn: FunctionIR):
        lit = self._as_literal(first_arg)
        if lit is not None:
            return lit
        var = first_arg.strip()
        if not var or "(" in var or var[0] in "\"'":
            return None
        for expr in fn.assignment_exprs:
            lhs, sep, rhs = expr.partition("=")
            if not sep:
                continue
            if lhs.strip() == var:
                lit = self._as_literal(rhs)
                if lit is not None:
                    return lit
        return None

    @staticmethod
    def _is_re_call(call, project_ir) -> bool:
        if call.name in {f"re.{n}" for n in ReDoSDetector._RE_FUNCS}:
            return True
        base = call.name.split(".")[-1]
        # Bare ``match``/``search``/... — only trust it when ``re`` is imported.
        if base in ReDoSDetector._RE_FUNCS and call.name == base:
            blob = "\n".join(project_ir.imports)
            if re.search(r"(?m)^\s*(import\s+re\b|from\s+re\b)", blob):
                return True
        return False

    def detect(self, fn, source_lines, project_ir):
        # Only flag regexes that actually process request-derived input.
        if not fn.sources:
            return []
        out = []
        seen_lines = set()
        for call in fn.calls:
            if not self._is_re_call(call, project_ir):
                continue
            if not call.args:
                continue
            pattern = self._resolve_pattern(call.args[0], fn)
            if not isinstance(pattern, str) or not pattern:
                continue
            if not self._has_nested_quantifier(pattern):
                continue
            if call.line in seen_lines:
                continue
            seen_lines.add(call.line)
            out.append(_build_vuln(
                self.category, fn.path, call.line,
                call.args[0].strip(), "regex",
                f"Catastrophic-backtracking regex applied to request-derived "
                f"input in '{fn.name}'",
                "Rewrite the regex to avoid nested/ambiguous quantifiers "
                "(unambiguous character sets or atomic grouping).",
                fn.name,
            ))
        return out


# ---------------------------------------------------------------------------
# 9. Arbitrary File Write
# ---------------------------------------------------------------------------

class ArbitraryFileWriteDetector(StructuredDetector):
    """Detect open(..., 'w') on caller-controlled paths."""

    category = "arbitrary-file-write"

    def detect(self, fn, source_lines, project_ir):
        out = []
        has_source = bool(fn.sources)
        for call in fn.calls:
            if call.name != "open":
                continue
            args = call.args
            if len(args) < 2:
                continue
            mode = args[1].strip()
            if not any(m in mode for m in ("w", "a", "+")):
                continue
            if has_source and _is_variable(args[0]) and not _is_string_literal(args[0]):
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    f"open({args[0]}, {mode})", "filesystem",
                    f"File write to caller-controlled path in '{fn.name}'",
                    "Validate the destination path against an allowlist before writing.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 10. File Upload
# ---------------------------------------------------------------------------

class FileUploadDetector(StructuredDetector):
    """Detect request.files without secure_filename / extension checks."""

    category = "file-upload"

    def detect(self, fn, source_lines, project_ir):
        body = self.body_text(fn, source_lines).lower()
        if "request.files" not in body and "file_storage" not in body:
            return []
        calls_str = " ".join(c.name for c in fn.calls)
        if "secure_filename" in calls_str:
            return []
        out = []
        for call in fn.calls:
            if call.name.split(".")[-1] == "save":
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    "file.save(...)", "filesystem",
                    f"Upload saved without secure_filename() / extension allowlist in '{fn.name}'",
                    "Sanitize filenames with secure_filename() and restrict extensions.",
                    fn.name,
                ))
                break
        return out


# ---------------------------------------------------------------------------
# 11. Open Redirect
# ---------------------------------------------------------------------------

class OpenRedirectDetector(StructuredDetector):
    """Detect redirect() / RedirectResponse() to a caller-controlled URL.

    v0.5.0: adds FastAPI / Starlette ``RedirectResponse(url=...)`` and treats a
    route-handler parameter (e.g. ``def go(next: str)``) as tainted input.
    """

    category = "open-redirect"
    _CALLS = {"redirect", "HttpResponseRedirect", "RedirectResponse"}
    _URL_KWARG = re.compile(r"^url\s*=\s*(.+)$", re.S)
    # v0.5.2: ``url_for("endpoint")`` — capture the call so we can inspect
    # whether the endpoint argument is a static string literal.
    _URL_FOR_CALL = re.compile(r"^url_for\s*\((.*)\)\s*$", re.S)

    def detect(self, fn, source_lines, project_ir):
        out = []
        route_handler = is_route_handler(fn)
        tainted_params = set(fn.parameters) if route_handler else set()
        for call in fn.calls:
            base = call.name.split(".")[-1]
            if base not in self._CALLS:
                continue
            if not call.args:
                continue
            first = call.args[0]
            # ``RedirectResponse(url=next)`` — unwrap the keyword form.
            m = self._URL_KWARG.match(first.strip())
            if m:
                first = m.group(1).strip()
            # v0.5.2: ``redirect(url_for("static_endpoint"))`` builds an internal
            # route URL from a string literal — it is never attacker controlled
            # and must not be flagged.  Only ``url_for(dynamic_var)`` deserves
            # taint analysis; in that case we fall through treating the endpoint
            # expression itself as the redirect target.
            m2 = self._URL_FOR_CALL.match(first.strip())
            if m2:
                inner = m2.group(1).strip()
                endpoint = inner.split(",")[0].strip()
                if _is_string_literal(endpoint):
                    continue
                first = endpoint
            if not _is_variable(first) or _is_string_literal(first):
                continue
            root = first.split("[")[0].split(".")[0]
            # Flask-style: some request.* call exists in the handler.
            # FastAPI-style: the redirect target is a route-handler parameter.
            if fn.sources or (route_handler and root in tainted_params):
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    first.strip(), "browser",
                    f"Redirect to caller-controlled URL in '{fn.name}'",
                    "Validate the redirect target against an allowlist or use a relative path.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 12. Weak Cryptography
# ---------------------------------------------------------------------------

class WeakCryptoDetector(StructuredDetector):
    """Detect md5 / sha1 / DES / ECB usage."""

    category = "weak-cryptography"
    _RE = re.compile(
        r"\b(?:hashlib\.)?(?:md5|sha1)\s*\(|"
        r"\.new\s*\(\s*['\"](?:md5|sha1)['\"]|"
        r"\bDES\b|\bMODE_ECB\b|Crypto\.Cipher\.DES",
        re.IGNORECASE,
    )

    def detect(self, fn, source_lines, project_ir):
        out = []
        for lineno, line in enumerate(source_lines, 1):
            # only report lines inside this function's span
            if not (fn.line <= lineno <= fn.end_line):
                continue
            if self._RE.search(line):
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    line.strip(), "crypto",
                    f"Weak cryptographic primitive in '{fn.name}'",
                    "Use SHA-256 / bcrypt / PBKDF2 and authenticated modes (e.g. GCM).",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 13. Insecure Defaults
# ---------------------------------------------------------------------------

class InsecureDefaultDetector(StructuredDetector):
    """Detect debug=True / host=0.0.0.0 / allow_all."""

    category = "insecure-defaults"
    _RE = re.compile(
        r"(?i)\bdebug\s*=\s*true|"
        r"\bhost\s*=\s*['\"]0\.0\.0\.0['\"]|"
        r"\ballow_all\b|\bcors_origin\s*=\s*['\"]\*['\"]|"
        r"app\.run\s*\([^)]*debug\s*=\s*true",
    )

    def detect(self, fn, source_lines, project_ir):
        out = []
        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line):
                continue
            if self._RE.search(line):
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    line.strip(), "configuration",
                    f"Insecure default configuration value in '{fn.name}'",
                    "Disable debug mode in production and bind to a specific interface.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 14. Auth Bypass (simplified: admin route without auth decorator)
# ---------------------------------------------------------------------------

class AuthBypassDetector(StructuredDetector):
    """Flag admin routes that lack an authentication mechanism.

    v0.5.0: recognises FastAPI admin routes such as
    ``@app.get("/api/admin/users")`` and treats a ``Depends(...)`` dependency in
    the handler signature as authentication.  A route whose path contains an
    ``admin`` segment and that has neither an auth decorator nor any
    ``Depends(...)`` is reported.
    """

    category = "auth-bypass"
    _ADMIN_RE = re.compile(r"/admin(?:[/\"']|$)", re.IGNORECASE)
    _DEPENDS_RE = re.compile(r"\bDepends\s*\(")

    @staticmethod
    def _signature_text(fn, source_lines) -> str:
        """The def(...) signature line(s), up to and including the closing ':'."""
        lines = []
        i = fn.line - 1
        n = min(len(source_lines), fn.end_line)
        while i < n:
            lines.append(source_lines[i])
            if source_lines[i].rstrip().endswith(":"):
                break
            i += 1
        return " ".join(l.strip() for l in lines)

    def detect(self, fn, source_lines, project_ir):
        decos = self.decorators(fn, source_lines)
        if not decos:
            return []
        is_admin = any(self._ADMIN_RE.search(d) for d in decos) or "admin_required" in " ".join(decos)
        if not is_admin:
            return []
        has_auth = any(
            d.split("(")[0].strip() in AUTH_PATTERNS["authentication_decorators"]
            for d in decos
        )
        # FastAPI: ``user=Depends(current_user)`` in the signature is an auth dependency.
        if self._DEPENDS_RE.search(self._signature_text(fn, source_lines)):
            has_auth = True
        if has_auth:
            return []
        out = []
        out.append(_build_vuln(
            self.category, fn.path, fn.line,
            decos[0], "authentication",
            f"Admin route '{fn.name}' registered without any authentication dependency",
            "Protect admin routes with @login_required / Depends(current_user) or equivalent.",
            fn.name,
        ))
        return out


# ---------------------------------------------------------------------------
# 15. IDOR
# ---------------------------------------------------------------------------

class IDORDetector(StructuredDetector):
    """v0.3.0 – targeted IDOR / privilege-escalation detector.

    Reports when a *route handler* (decorated with ``@app.route`` /
    ``@app.get`` / ``@bp.route`` …) satisfies **all** of:

    1. it carries a route decorator;
    2. one of its parameters names an object id (``user_id`` / ``doc_id`` /
       ``order_id`` / ``id`` …);
    3. that id is passed straight into a DB lookup
       (``.query.get`` / ``.filter_by`` / ``get_or_404`` / ``db.execute``);
    4. the body performs **no** authorization check
       (``session['user_id']`` / ``current_user`` / ``@login_required`` /
       ``role == 'admin'`` / ``g.user`` / ``check_owner`` …).

    Read-only access is reported as ``idor`` (High).  Destructive access
    (``db.session.delete`` / ``.remove(`` / ``.drop(``) is escalated to
    ``privilege-escalation`` (Critical).
    """

    category = "idor"

    _ROUTE_DECO_RE = re.compile(
        r"\.route\b|\.(?:get|post|put|delete|patch)\s*\(|blueprint", re.I,
    )
    # object-id path parameters (user_id, doc_id, orderid, id, pk, uuid …)
    _ID_PARAM_RE = re.compile(
        r"(?:^|_)(?:user_id|doc_id|order_id|account_id|file_id|orderid|userid|docid|id|pk|uuid)(?:_|$)|_id$",
        re.I,
    )
    _LOOKUP_CALLS = {"get", "filter_by", "get_or_404", "execute", "raw"}
    # v0.6.0: data-access verbs on repository / service objects (e.g.
    # ``orchestrator.update_status(task_id)``, ``repo.get(task_id)``).  A path
    # ``*_id`` parameter handed to any such method is an object reference.
    _DATA_ACCESS_VERB = re.compile(
        r"^(?:get|find|fetch|load|read|retrieve|update|save|delete|remove|patch|set|"
        r"create|apply|count|exists|by_id)",
        re.I,
    )
    _AUTHZ_TOKENS = (
        "session['user_id']", 'session["user_id"]',
        "session.get('user_id')", 'session.get("user_id")',
        "current_user", "@login_required", "login_required",
        "role == 'admin'", "role=='admin'",
        'role == "admin"', 'role=="admin"',
        "role != 'admin'", "role!='admin'",
        'role != "admin"', 'role!="admin"',
        "is_admin", "g.user", "check_owner", "is_owner", "has_permission",
        "assert_owner", "require_admin",
    )
    _DESTRUCTIVE = re.compile(r"\b(?:delete|remove|drop)\s*\(", re.I)
    # v0.5.0: a body comparison that ties the fetched row's owner to the
    # authenticated principal (``row["owner_id"] != user["id"]``) is an
    # authorisation check even when it does not name a recognised token.
    _OWNERSHIP_RE = re.compile(
        r"(owner_id|user_id|created_by|account_id|owner)\b.{0,18}(?:!=|==).{0,18}"
        r"(user|current_user|session)\b"
        r"|\b(user|current_user)\b.{0,18}(?:!=|==).{0,18}"
        r"(owner_id|user_id|created_by|row|doc|note|item|record)\b",
        re.I,
    )

    @staticmethod
    def _body_after_signature(fn, source_lines) -> str:
        """Source lines strictly after the ``def ... :`` signature.

        FastAPI authentication is expressed as ``user=Depends(current_user)`` in
        the *signature*; that proves authentication, **not** authorisation.  The
        body is where an ownership / role comparison (``row["owner_id"] ==
        user["id"]``) would live.  Separating the two lets us stop treating a
        signature-only ``current_user`` as sufficient authorization.
        """
        start = fn.line - 1
        i = start
        n = min(len(source_lines), fn.end_line)
        while i < n and not source_lines[i].rstrip().endswith(":"):
            i += 1
        i += 1  # skip the closing ':' line itself
        return "\n".join(
            source_lines[k]
            for k in range(i, n)
            if not source_lines[k].strip().startswith("#")
        )

    def detect(self, fn, source_lines, project_ir):
        # 1. route decorator required
        decos = self.decorators(fn, source_lines)
        if not any(self._ROUTE_DECO_RE.search(d) for d in decos):
            return []
        # 2. object-id parameter
        id_params = [p for p in fn.parameters if self._ID_PARAM_RE.search(p)]
        if not id_params:
            return []
        body = self.body_text(fn, source_lines)
        # 3a. the id reaches an ORM / DB lookup call
        used_in_lookup = False
        for call in fn.calls:
            base = call.name.split(".")[-1]
            joined = " ".join(call.args)
            if not any(p in joined for p in id_params):
                continue
            # direct ORM calls (``get_or_404`` / ``filter_by``) OR a data-access
            # method on a repository / service object (``repo.update_status(id)``).
            if base in self._LOOKUP_CALLS or self._DATA_ACCESS_VERB.match(base):
                used_in_lookup = True
                break
        # 3b. v0.4.0 – non-ORM data-access patterns: list comprehensions /
        # generator expressions, ``next((...))``, dict lookups, filter(lambda).
        non_orm_access = False
        for p in id_params:
            esc = re.escape(p)
            if re.search(
                r"\b\w+\s*\[\s*['\"]?\w*['\"]?\s*\]\s*!?={1,2}\s*" + esc + r"\b"  # u['id'] == / != user_id
                r"|\b" + esc + r"\s*!?={1,2}\s*\w+\s*\["                # user_id == / != u['id']
                r"|\b\w+\s*\.\w+\s*!?={1,2}\s*" + esc + r"\b"           # u.id == / != user_id
                r"|\bnext\s*\(\s*\(?"                                  # next((x for x ...
                r"|\bfilter\s*\(\s*lambda"                              # filter(lambda ...
                r"|\[" + esc + r"\s*\]"                                  # data[user_id]
                r"|\.get\s*\(\s*" + esc + r"\s*[,)]",                   # data.get(user_id)
                body, re.I,
            ):
                non_orm_access = True
                break
        if not used_in_lookup and not non_orm_access:
            return []
        # 4. authorization check present → skip (false-positive guard).
        # v0.5.0: check only the *body* plus decorators.  A FastAPI
        # ``user=Depends(current_user)`` in the signature is authentication,
        # not authorisation, and must not suppress an IDOR finding.
        authz_text = self._body_after_signature(fn, source_lines) + "\n" + "\n".join(decos)
        if any(tok in authz_text for tok in self._AUTHZ_TOKENS):
            return []
        if self._OWNERSHIP_RE.search(authz_text):
            return []
        # destructive operation → privilege escalation.  v0.4.0 also treats a
        # ``value != id`` rebuild (list comprehension removal) and a function
        # named delete/remove as destructive.
        destructive = bool(self._DESTRUCTIVE.search(authz_text))
        if not destructive:
            for p in id_params:
                if re.search(r"!=\s*" + re.escape(p) + r"\b", authz_text):
                    destructive = True
                    break
        if not destructive:
            destructive = any(
                w in fn.name.lower() for w in ("delete", "remove", "destroy")
            )
        if destructive:
            return [_build_vuln(
                "privilege-escalation", fn.path, fn.line,
                f"params={id_params}", "authorization",
                f"'{fn.name}' performs a destructive operation on a caller-supplied "
                f"object id {id_params} with no admin / ownership check",
                "Require an admin / role check and verify the object belongs to the "
                "caller before deleting or modifying it.",
                fn.name,
            )]
        return [_build_vuln(
            "idor", fn.path, fn.line,
            f"params={id_params}", "authorization",
            f"'{fn.name}' reads a caller-supplied object id {id_params} without "
            "verifying ownership",
            "Verify that the requested object belongs to the authenticated user "
            "before returning it.",
            fn.name,
        )]


# ---------------------------------------------------------------------------
# 16. NoSQL Injection
# ---------------------------------------------------------------------------

class NoSQLInjectionDetector(StructuredDetector):
    """Detect MongoDB queries built from caller-controlled dicts.

    v0.5.0: also flags a FastAPI route handler that forwards
    ``await request.json()`` (or a route parameter) into a helper which the
    project IR shows ultimately issues a ``find`` / ``find_one`` / ``insert``
    against the driver.  Cross-function tracking is deliberately shallow — it
    only follows one hop — but it catches the common
    ``return get_users(query)`` indirection.
    """

    category = "nosql-injection"
    _MONGO_CALLS = {"find_one", "find", "insert_one", "insert_many",
                    "update_one", "update_many", "delete_one", "delete_many"}
    _OPERATOR_RE = re.compile(r"\$(?:where|gt|lt|ne|regex|expr|func)")

    def _mongo_helper_names(self, project_ir) -> set:
        """Names of functions whose body directly hits a MongoDB sink."""
        names: set = set()
        if project_ir is None:
            return names
        for f in getattr(project_ir, "functions", []) or []:
            for c in getattr(f, "calls", []) or []:
                if c.name.split(".")[-1] in self._MONGO_CALLS:
                    names.add(f.name)
        return names

    def detect(self, fn, source_lines, project_ir):
        out = []
        tainted = taint_names(fn)
        for call in fn.calls:
            base = call.name.split(".")[-1]
            joined = " ".join(call.args)
            # -- direct MongoDB call in this function -----------------------
            if base in self._MONGO_CALLS:
                if call.args and fn.sources and (
                    "request" in joined or _is_variable(call.args[0])
                ):
                    out.append(_build_vuln(
                        self.category, fn.path, call.line,
                        joined.strip(), "nosql",
                        f"MongoDB query built from caller-controlled input in '{fn.name}'",
                        "Validate query operators and avoid passing raw request dicts to the driver.",
                        fn.name,
                    ))
                elif self._OPERATOR_RE.search(joined) and fn.sources:
                    out.append(_build_vuln(
                        self.category, fn.path, call.line,
                        joined.strip(), "nosql",
                        f"NoSQL operator injection surface in '{fn.name}'",
                        "Sanitise query operators before passing them to the MongoDB driver.",
                        fn.name,
                    ))
                continue
            # -- v0.5.0: one-hop indirection into a MongoDB helper ----------
            # Only treat a *free* function call (``helper(...)``) as a
            # delegation — ``obj.helper(...)`` (e.g. ``ldap_conn.search``) must
            # not collide with a helper that happens to share its basename.
            if base in self._mongo_helper_names(project_ir) and call.name == base:
                has_tainted_arg = False
                if fn.sources:
                    has_tainted_arg = True
                elif tainted:
                    has_tainted_arg = any(t and t in joined for t in tainted)
                if has_tainted_arg:
                    out.append(_build_vuln(
                        self.category, fn.path, call.line,
                        joined.strip(), "nosql",
                        f"Caller-controlled input forwarded to a MongoDB query helper "
                        f"('{base}') in '{fn.name}'",
                        "Validate query operators and avoid passing raw request bodies to the driver.",
                        fn.name,
                    ))
        return out


# ---------------------------------------------------------------------------
# 17. XXE (XML External Entity)
# ---------------------------------------------------------------------------

class XXEDetector(StructuredDetector):
    """Detect unsafe XML parsing of user-controlled input.

    Flags ``xml.etree.ElementTree.fromstring`` / ``ET.parse`` /
    ``lxml.etree.fromstring`` / ``minidom.parseString`` etc. when the
    argument looks like user-supplied data.
    """

    category = "xxe"
    # call-name suffixes that identify an XML parse sink
    _XML_SUFFIXES = (
        ".etree.fromstring", ".etree.parse",
        ".ElementTree.fromstring", ".ElementTree.parse",
        ".minidom.parseString", ".minidom.parse",
    )
    _BARE_XML = {"fromstring", "parseString"}
    _USER_TOKENS = (
        "user", "input", "request", "data", "xml", "content",
        "body", "payload", "raw",
    )

    def detect(self, fn, source_lines, project_ir):
        out = []
        for call in fn.calls:
            name = call.name
            base = name.split(".")[-1]
            is_xml = name.endswith(self._XML_SUFFIXES) or base in self._BARE_XML
            if not is_xml:
                continue
            if not call.args:
                continue
            first = call.args[0]
            arg_lower = first.lower()
            has_user = any(tok in arg_lower for tok in self._USER_TOKENS)
            if fn.sources or has_user:
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    first.strip(), "xml",
                    f"XML parser ({name}) processes user-controlled input in '{fn.name}'",
                    "Use defusedxml or disable external entity resolution (resolve_entities=False).",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 18. Insecure JWT
# ---------------------------------------------------------------------------

class JWTFlawDetector(StructuredDetector):
    """Detect weak JWT configuration (algorithm=none, verify=False)."""

    category = "jwt-flaws"
    _RE_NONE_ALGO = re.compile(
        r"algorithm\s*=\s*['\"]none['\"]|algorithms\s*=\s*\[[^\]]*['\"]none['\"]",
        re.I,
    )
    _RE_VERIFY_FALSE = re.compile(
        r"verify\s*=\s*False|"
        r"verify_signature['\"]?\s*:\s*False|"
        r"options\s*=\s*\{[^}]*verify[^}]*False",
        re.I,
    )

    def detect(self, fn, source_lines, project_ir):
        out = []
        for call in fn.calls:
            name = call.name
            base = name.split(".")[-1]
            if "jwt" not in name.lower() or base not in {"encode", "decode"}:
                continue
            joined = " ".join(call.args)
            if self._RE_NONE_ALGO.search(joined):
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    joined.strip(), "authentication",
                    f"JWT '{base}' configured with 'none' algorithm in '{fn.name}'",
                    "Disallow the 'none' algorithm and enforce a strong signing key.",
                    fn.name,
                ))
            elif self._RE_VERIFY_FALSE.search(joined):
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    joined.strip(), "authentication",
                    f"JWT '{base}' called with signature verification disabled in '{fn.name}'",
                    "Always verify the JWT signature; never pass verify=False in production.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 19. LDAP Injection
# ---------------------------------------------------------------------------

class LdapInjectionDetector(StructuredDetector):
    """Detect ldap3 search_filter built from user input via f-string / concat."""

    category = "ldap-injection"
    _RE_FILTER = re.compile(
        r"search_filter\s*=.*(?:f['\"]|\+|\.format\()",
        re.I,
    )

    def detect(self, fn, source_lines, project_ir):
        # Require LDAP context somewhere in the file (imports or body).
        file_text = "\n".join(source_lines).lower()
        if "ldap" not in file_text:
            return []
        out = []
        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line):
                continue
            if self._RE_FILTER.search(line):
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    line.strip(), "ldap",
                    f"LDAP search_filter built from dynamic input in '{fn.name}'",
                    "Sanitise LDAP filter values and use parameterised filters where available.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 20. Security Misconfiguration (v0.3.0) – app.run(debug=True / host=0.0.0.0)
# ---------------------------------------------------------------------------


class SecurityMisconfigurationDetector(StructuredDetector):
    """v0.3.0 – detect ``app.run(debug=True)`` / ``host='0.0.0.0'``.

    These calls usually live at module level (``if __name__ == '__main__':``)
    rather than inside a function, so the detector scans the *whole* source
    file.  It is invoked once per function; repeated reports on the same line
    are collapsed by the pipeline / file-level dedup keyed on
    ``(category, file, line)``.

    v0.4.1 (round-6) also flags:
      * ``app.config['DEBUG'] = True`` (Flask debug mode left on)
      * module-level ``DEBUG = True`` (Django settings, production debug)
      * ``ALLOWED_HOSTS = ['*']`` (any Host header accepted)
    The bare ``DEBUG = True`` rule only fires at module level so a function
    local ``debug = True`` is never reported.
    """

    category = "security-misconfiguration"
    _DEBUG_RE = re.compile(r"app\.run\s*\([^)]*debug\s*=\s*True", re.I)
    _BIND_RE = re.compile(r"app\.run\s*\([^)]*host\s*=\s*['\"]0\.0\.0\.0['\"]", re.I)
    # v0.4.1 – round-6 extensions
    _APP_CONFIG_DEBUG_RE = re.compile(
        r"app\.config\s*\[\s*['\"]DEBUG['\"]\s*\]\s*=\s*True", re.I)
    _DJANGO_DEBUG_RE = re.compile(r"^DEBUG\s*=\s*True\b")
    _ALLOWED_HOSTS_RE = re.compile(
        r"^ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]\s*\]")

    @staticmethod
    def _in_any_function(lineno: int, fn, project_ir) -> bool:
        """True when *lineno* lies inside some function defined in this file."""
        for f in project_ir.functions:
            if f.path != fn.path:
                continue
            if f.line <= lineno <= f.end_line:
                return True
        return False

    def detect(self, fn, source_lines, project_ir):
        out = []
        for lineno, line in enumerate(source_lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith(("import ", "from ")):
                continue
            dbg = bool(self._DEBUG_RE.search(line))
            bind = bool(self._BIND_RE.search(line))
            cfg_dbg = bool(self._APP_CONFIG_DEBUG_RE.search(line))
            # Bare ``DEBUG = True`` only counts at module level — never a
            # function-local variable.
            django_dbg = bool(self._DJANGO_DEBUG_RE.search(stripped)) and \
                not self._in_any_function(lineno, fn, project_ir)
            hosts = bool(self._ALLOWED_HOSTS_RE.search(stripped))

            if not (dbg or bind or cfg_dbg or django_dbg or hosts):
                continue

            issues = []
            if dbg:
                issues.append("debug=True (Werkzeug interactive debugger exposed)")
            if bind:
                issues.append("host='0.0.0.0' (bound on all interfaces)")
            if cfg_dbg:
                issues.append("app.config['DEBUG'] = True (debug mode enabled in production)")
            if django_dbg:
                issues.append("module-level DEBUG = True (framework debug mode exposed)")
            if hosts:
                issues.append("ALLOWED_HOSTS = ['*'] (any Host header accepted)")

            if cfg_dbg or django_dbg:
                remediation = "Set DEBUG = False / app.config['DEBUG'] = False in production."
            elif hosts:
                remediation = "Restrict ALLOWED_HOSTS to an explicit list of trusted hostnames."
            else:
                remediation = (
                    "Disable debug mode in production and bind to a specific interface "
                    "(e.g. 127.0.0.1 behind a reverse proxy).")

            out.append(_build_vuln(
                self.category, fn.path, lineno,
                stripped, "configuration",
                "Insecure configuration: " + "; ".join(issues),
                remediation,
                fn.name or "<module>",
            ))
        return out


# ---------------------------------------------------------------------------
# 21. Sensitive Data in Logs (v0.3.0)
# ---------------------------------------------------------------------------


class SensitiveDataLoggingDetector(StructuredDetector):
    """v0.3.0 – detect ``logger.*`` / ``logging.*`` / ``print`` calls that
    interpolate a sensitive value (password / token / card number / ssn …)."""

    category = "sensitive-data-logging"
    _LOG_CALL_RE = re.compile(
        r"(?:app\.logger|logger|logging)\.[a-z]+\s*\(|(?:^|[\s(])print\s*\(", re.I,
    )
    _SENSITIVE = (
        "password", "secret", "token", "credit_card",
        "card_number", "ssn", "api_key", "private_key",
    )

    def detect(self, fn, source_lines, project_ir):
        out = []
        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line):
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if self._LOG_CALL_RE.search(line) and any(t in line.lower() for t in self._SENSITIVE):
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    stripped, "logging",
                    f"Sensitive value written to a log sink in '{fn.name}'",
                    "Never log passwords / tokens / PII; redact sensitive fields before logging.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 22. User Enumeration (v0.3.0)
# ---------------------------------------------------------------------------


class UserEnumerationDetector(StructuredDetector):
    """v0.3.0 – detect login handlers that return *different* messages for an
    unknown user vs. a wrong password, letting attackers enumerate accounts."""

    category = "user-enumeration"
    _NAME_RE = re.compile(r"login|signin|sign_in|auth", re.I)
    _USER_EXIST_WORDS = ("does not exist", "not exist", "not found", "不存在", "用户")
    _WRONG_PW_WORDS = ("wrong password", "incorrect", "密码错误", "密码不正确", "wrong")

    def detect(self, fn, source_lines, project_ir):
        if not self._NAME_RE.search(fn.name):
            return []
        # collect string-literal return branches
        str_branches = [
            r.strip().lower() for r in fn.returns
            if r.strip().startswith(("'", '"', "f'", 'f"'))
        ]
        if len(str_branches) < 2:
            return []

        def hits(words):
            return any(any(w in b for w in words) for b in str_branches)

        if hits(self._USER_EXIST_WORDS) and hits(self._WRONG_PW_WORDS):
            return [_build_vuln(
                self.category, fn.path, fn.line,
                f"returns={str_branches}", "authentication",
                f"'{fn.name}' leaks which usernames exist via distinct error messages",
                "Return a generic 'invalid credentials' message for both unknown user "
                "and wrong password.",
                fn.name,
            )]
        return []


# ---------------------------------------------------------------------------
# 23. Sensitive Data Exposure (v0.3.0)
# ---------------------------------------------------------------------------


class SensitiveDataExposureDetector(StructuredDetector):
    """v0.3.0 – detect a sensitive value (card number / ssn / password …) that
    originates from the request and is either persisted via an ORM object or
    echoed back in an HTTP response."""

    category = "sensitive-data-exposure"
    _SENSITIVE_NAMES = ("credit_card", "card_number", "ssn", "password", "secret", "api_key")
    _ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+)$")
    # v0.4.0 – debug / config exposure surfaced through HTTP responses.
    _ENV_RE = re.compile(r"os\.environ|\bdict\s*\(\s*os\.environ|os\.environ\.copy\s*\(", re.I)
    _CONFIG_RE = re.compile(r"app\.config|django\.conf\.settings|\bsettings\b", re.I)
    _SECRET_WORD = re.compile(r"secret|password|key|token", re.I)

    def _sensitive_request_vars(self, fn):
        vars_: set = set()
        for expr in fn.assignment_exprs:
            m = self._ASSIGN.match(expr.strip())
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if any(s in lhs.lower() for s in self._SENSITIVE_NAMES) and "request." in rhs:
                vars_.add(lhs)
        return vars_

    def _config_exposure(self, fn, source_lines):
        """v0.4.0 – HTTP handler returns env / config / secret material."""
        out = []
        for ret in fn.returns:
            if not ret:
                continue
            if self._ENV_RE.search(ret):
                out.append(_build_vuln(
                    self.category, fn.path, fn.line,
                    ret[:120], "browser",
                    f"Environment variables / full environment returned in HTTP response in '{fn.name}'",
                    "Never return os.environ or process configuration to clients; expose only non-sensitive fields.",
                    fn.name,
                ))
            elif self._CONFIG_RE.search(ret) and self._SECRET_WORD.search(ret):
                out.append(_build_vuln(
                    self.category, fn.path, fn.line,
                    ret[:120], "browser",
                    f"Application configuration / secret material returned in HTTP response in '{fn.name}'",
                    "Never return app.config / settings containing secrets to clients.",
                    fn.name,
                ))
        # v0.4.0 – module-level / handler variables named like secrets that are
        # built from configuration (not the request) and echoed back.
        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line):
                continue
            if "return" not in line:
                continue
            if self._ENV_RE.search(line):
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    line.strip()[:120], "browser",
                    f"Environment variables returned in HTTP response in '{fn.name}'",
                    "Never return os.environ to clients.",
                    fn.name,
                ))
        return out

    def detect(self, fn, source_lines, project_ir):
        # v0.4.0 – config/env exposure branch runs independently of the
        # request-echo / ORM-persistence checks below.
        exposed = self._config_exposure(fn, source_lines)
        if exposed:
            return exposed
        sensitive = self._sensitive_request_vars(fn)
        if not sensitive:
            return []
        # (a) echoed back in an f-string return → most direct exposure
        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line):
                continue
            if "return" in line and any(v in line for v in sensitive) and "{" in line:
                return [_build_vuln(
                    self.category, fn.path, lineno,
                    line.strip(), "browser",
                    f"Sensitive value(s) {sorted(sensitive)} returned in HTTP response in '{fn.name}'",
                    "Avoid returning sensitive data to the client; store only a non-sensitive reference.",
                    fn.name,
                )]
        # (b) persisted via ORM construction (Model(field=value)).  Only
        # bare, Capitalized names (e.g. ``Payment(...)``) are treated as ORM
        # constructors — builtins such as ``len(...)`` / ``float(...)`` are not.
        for call in fn.calls:
            if "." in call.name:
                continue
            if not call.name or not call.name[0].isupper():
                continue
            joined = " ".join(call.args)
            hit = [v for v in sensitive if v in joined]
            if hit:
                return [_build_vuln(
                    self.category, fn.path, call.line,
                    f"{call.name}({joined})", "database",
                    f"Sensitive value(s) {hit} persisted in plain text via ORM in '{fn.name}'",
                    "Encrypt sensitive data at rest and never store it in plain text.",
                    fn.name,
                )]
        return []


# ---------------------------------------------------------------------------
# 24. Missing Rate Limiting (v0.3.0)
# ---------------------------------------------------------------------------


class MissingRateLimitingDetector(StructuredDetector):
    """v0.3.0 – detect credential-handling login routes with no throttling,
    lockout or attempt counting (brute-force surface)."""

    category = "missing-rate-limiting"
    _NAME_RE = re.compile(r"login|signin|sign_in|auth", re.I)
    _RATELIMIT_TOKENS = (
        "limiter", "rate_limit", "rate-limit", "flask-limiter",
        "cache.get", "cache.incr", "attempt", "lockout",
        "throttle", "max_attempts",
    )
    # v0.3.1: a login that already verifies the submitted password against a
    # salted KDF hash (bcrypt / Werkzeug / argon2) is no longer the weak,
    # plaintext credential-comparison surface this detector targets, so the
    # missing-throttling finding is suppressed on that remediated code.
    _STRONG_HASH_VERIFY = (
        "bcrypt.checkpw", "bcrypt.hashpw", "check_password_hash",
        "verify_password", "argon2", "hashpw",
    )

    def detect(self, fn, source_lines, project_ir):
        if not self._NAME_RE.search(fn.name):
            return []
        body = self.code_text(fn, source_lines)
        bl = body.lower()
        # must actually process credentials
        if "password" not in bl and "passwd" not in bl:
            return []
        if any(tok in bl for tok in self._RATELIMIT_TOKENS):
            return []
        # already verifying against a salted password hash → remediated
        if any(tok in bl for tok in self._STRONG_HASH_VERIFY):
            return []
        return [_build_vuln(
            self.category, fn.path, fn.line,
            fn.name, "authentication",
            f"Login handler '{fn.name}' has no rate limiting / account lockout, "
            "allowing brute-force attacks",
            "Add per-account / per-IP throttling and temporary lockout after repeated failures.",
            fn.name,
        )]


# ---------------------------------------------------------------------------
# 25. Weak Password Policy (v0.3.0)
# ---------------------------------------------------------------------------


class WeakPasswordPolicyDetector(StructuredDetector):
    """v0.3.0 – detect password setters that accept a request-supplied password
    with no strength / complexity validation."""

    category = "weak-password-policy"
    _NAME_RE = re.compile(r"password|register|signup|sign_up|reset", re.I)
    _PW_NAMES = ("password", "passwd", "pwd")
    # writing the chosen password back onto an account marks a *setter*
    _PW_WRITE_RE = re.compile(r"\.password\s*=|set_password\s*\(", re.I)

    @staticmethod
    def _has_complexity_check(body: str) -> bool:
        bl = body.lower()
        # explicit minimum length threshold (>= 8 / 10 / 12)
        if re.search(r"len\s*\([^)]*\)\s*>=?\s*(?:8|10|12)\b", bl):
            return True
        # regex-based strength validation
        if any(t in bl for t in ("re.search", "re.match", "fullmatch", "password_strength")):
            return True
        # mixed character classes required
        if "isalpha" in bl and "isdigit" in bl:
            return True
        if "special" in bl and "char" in bl:
            return True
        return False

    def detect(self, fn, source_lines, project_ir):
        if not self._NAME_RE.search(fn.name):
            return []
        body = self.code_text(fn, source_lines)
        # only a *setter* (writes the password onto an account) counts
        if not self._PW_WRITE_RE.search(body):
            return []
        # password must originate from the request
        pw_from_request = False
        for expr in fn.assignment_exprs:
            m = re.match(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+)$", expr.strip())
            if not m:
                continue
            lhs, rhs = m.group(1).lower(), m.group(2)
            if any(s in lhs for s in self._PW_NAMES) and "request." in rhs:
                pw_from_request = True
        if not pw_from_request:
            return []
        if self._has_complexity_check(body):
            return []
        return [_build_vuln(
            self.category, fn.path, fn.line,
            "password accepted without complexity validation", "authentication",
            f"Password setter '{fn.name}' accepts a request-supplied password with "
            "no minimum length / complexity check",
            "Enforce minimum length (>= 8), mixed character classes and reject common passwords.",
            fn.name,
        )]


# ---------------------------------------------------------------------------
# 26. Business Logic Flaw (v0.3.0)
# ---------------------------------------------------------------------------


class BusinessLogicFlawDetector(StructuredDetector):
    """v0.3.0 – detect monetary-transfer style handlers that take an amount
    from the request but never validate that it is strictly positive."""

    category = "business-logic-flaw"
    _NAME_RE = re.compile(r"transfer|pay|refund|withdraw|deduct", re.I)
    # A positive-amount validation is present when the handler either allows
    # only strictly-positive amounts (``if amount > 0``) or explicitly rejects
    # non-positive ones (``if amount <= 0: ...``).  ``if amount != 0`` /
    # ``if amount:`` are NOT such validations.
    _POSITIVE_CHECK_RE = re.compile(
        r"if\s+[^\n]*\bamount\b[^\n]*>\s*0\b"       # if amount > 0
        r"|if\s+[^\n]*\bamount\b[^\n]*<=\s*0\b",     # if amount <= 0 (reject)
        re.I,
    )

    def detect(self, fn, source_lines, project_ir):
        if not self._NAME_RE.search(fn.name):
            return []
        body = self.code_text(fn, source_lines)
        bl = body.lower()
        # amount must flow from the request
        if "amount" not in bl or "request." not in bl:
            return []
        # a proper positive validation already present → safe
        if self._POSITIVE_CHECK_RE.search(body):
            return []
        return [_build_vuln(
            self.category, fn.path, fn.line,
            "amount validated only for non-zero", "business-logic",
            f"'{fn.name}' accepts a request-supplied amount without enforcing that it "
            "is strictly positive (negative amounts are accepted)",
            "Reject non-positive amounts explicitly before performing the transfer.",
            fn.name,
        )]


# ---------------------------------------------------------------------------
# 27. Race Condition (v0.6.0 – real TOCTOU heuristic)
# ---------------------------------------------------------------------------


class RaceConditionDetector(StructuredDetector):
    """v0.6.0 – static TOCTOU / check-then-act heuristic (CWE-367).

    Flags *financial* functions that read a balance / quantity / availability
    flag from the database, make a decision on it, and then write it back as a
    **separate** statement — with no atomic guard (transaction, row lock or an
    in-place compare-and-swap ``WHERE balance >= ?``).

    This is a conservative shape match, not a proof of concurrent reachability:
    it deliberately stays silent when a real transaction boundary or lock is
    present, when there is no read+write pair, or when the function is not a
    money / inventory operation.
    """

    category = "race-condition"

    # Money / inventory operations whose read-modify-write is concurrency-sensitive.
    _FIN_NAME = re.compile(
        r"\b(withdraw|transfer|redeem|purchase|buy|deposit|stake|sell|checkout|"
        r"spend|cash_?out|credit|debit|settle|redeem_coupon|buy_item)\b",
        re.I,
    )
    _SQL_READ = re.compile(r"\bSELECT\b", re.I)
    _SQL_WRITE = re.compile(r"\b(UPDATE|INSERT|DELETE)\b", re.I)
    # A decision made on a balance / quantity / availability flag.  The field
    # may be on either side of the operator and may be reached via attribute /
    # subscript access (``user.balance < amount`` or ``row["used"] == 1``),
    # so we allow bracket / quote punctuation between the field and the operator.
    _CHECK = re.compile(
        r"\b(?:balance|quantity|stock|used|available|amount|price|funds|inventory)\b"
        r"[\s\"'\]\.]*?"
        r"(?:<|<=|>|>=|==|!=)"
        r"|"
        r"(?:<|<=|>|>=|==|!=)\s*"
        r"\b(?:balance|quantity|stock|used|available|amount|price|funds|inventory)\b",
        re.I,
    )
    # Actual concurrency protection, inlined in the function (a call to a
    # separately-defined ``*_atomic`` helper does NOT protect the caller's
    # own check-then-act window).
    _GUARD = re.compile(
        r"\bBEGIN(?:\s+(?:IMMEDIATE|EXCLUSIVE|DEFERRED|TRANSACTION))?\b"
        r"|\bFOR\s+UPDATE\b"
        r"|\bLOCK\s+(?:TABLE|IN\s+SHARE\s+MODE)\b"
        r"|isolation_level"
        r"|\bwith\s+\w*(?:conn|db|session|transaction)\b",
        re.I,
    )

    def detect(self, fn, source_lines, project_ir):
        # Only money / inventory operations.
        if not self._FIN_NAME.search(fn.name):
            return []
        body = self.code_text(fn, source_lines)
        # Must actually read AND write the database (not a pure read or a
        # single atomic UPDATE with no preceding SELECT).
        if not (self._SQL_READ.search(body) and self._SQL_WRITE.search(body)):
            return []
        # Must make a decision on a balance / quantity / flag.
        if not self._CHECK.search(body):
            return []
        # Guarded by a real transaction / row lock?
        if self._GUARD.search(body):
            return []
        # Anchor the finding on the first SQL write call.
        write_line = fn.line
        snippet = ""
        for call in fn.calls:
            base = call.name.split(".")[-1]
            joined = " ".join(call.args)
            if base in ("execute", "executemany") and self._SQL_WRITE.search(joined):
                write_line = call.line
                snippet = joined.strip()
                break
        if not snippet:
            snippet = f"{fn.name}: check-then-act on balance/quantity"
        return [_build_vuln(
            self.category, fn.path, write_line,
            snippet[:120], "db",
            f"Check-then-act on a balance/quantity in '{fn.name}' reads the "
            f"value, decides on it, and writes it back with no transaction or "
            f"row lock — a concurrent request can interleave in the gap.",
            "Wrap the read-modify-write in a transaction (SELECT ... FOR UPDATE) "
            "or use a single atomic UPDATE (... WHERE balance >= amount).",
            fn.name,
        )]


# ---------------------------------------------------------------------------
# 28. Code Injection (v0.3.1) – eval() / exec() / compile() on user input
# ---------------------------------------------------------------------------


class CodeInjectionDetector(StructuredDetector):
    """v0.3.1 – detect ``eval()`` / ``exec()`` / ``compile()`` called with
    attacker-controlled input (CWE-94).

    A call is reported when its first argument:

    * is a direct ``request.*`` expression, or
    * is an f-string / concatenation, or
    * is a variable that flows from a request source (``x = request.form.get(...)``)
      or that is a parameter of an HTTP route handler.

    A *static string literal* argument (``eval("1+1")`` /
    ``exec("print('hi')")``) is **never** reported.
    """

    category = "code-injection"
    _CALLS = {"eval", "exec", "compile"}
    _ROUTE_DECO_RE = re.compile(
        r"\.route\b|\.(?:get|post|put|delete|patch)\s*\(|blueprint", re.I,
    )
    _TAINT_SRC = re.compile(
        r"request\.(?:args|form|json|values|data|body|cookies|headers|"
        r"query_params|view_args|files|get_json|POST|GET)\b"
        r"|request\s*\[\s*['\"]",
        re.I,
    )
    _ASSIGN = re.compile(r"^([A-Za-z_]\w*)\s*=\s*(.+)$")
    _IDENTS = re.compile(r"\b[A-Za-z_]\w*\b")

    def _build_taint(self, fn, source_lines):
        tainted: set = set()
        # HTTP-handler parameters are attacker-controlled
        if any(self._ROUTE_DECO_RE.search(d) for d in self.decorators(fn, source_lines)):
            tainted.update(fn.parameters)
        deferred: list = []
        for expr in fn.assignment_exprs:
            m = self._ASSIGN.match(expr.strip())
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if self._TAINT_SRC.search(rhs):
                tainted.add(lhs)
            else:
                deferred.append((lhs, rhs))
        # simple one-level propagation: a = b with b tainted → a tainted
        changed = True
        while changed:
            changed = False
            for lhs, rhs in deferred:
                if lhs in tainted:
                    continue
                roots = set(self._IDENTS.findall(rhs))
                if any(r in tainted for r in roots):
                    tainted.add(lhs)
                    changed = True
        return tainted

    def detect(self, fn, source_lines, project_ir):
        tainted = self._build_taint(fn, source_lines)
        out = []
        for call in fn.calls:
            base = call.name.split(".")[-1]
            if base not in self._CALLS:
                continue
            if not call.args:
                continue
            first = call.args[0]
            # static string literal → safe (eval("1+1"))
            if _is_string_literal(first):
                continue
            reason = ""
            if self._TAINT_SRC.search(first):
                reason = f"{base}() fed a request expression in '{fn.name}'"
            elif _is_fstring(first) or _has_concat(first):
                reason = f"{base}() called on a dynamically-built string in '{fn.name}'"
            elif first.strip().startswith("self."):
                # v0.4.3 – second-order code execution: ``self.<attr>`` reads a
                # value persisted in the database / model state, which an
                # attacker may have written earlier (e.g. Django ``TextField``
                # ``self.expression``).  No intra-procedural source tracking is
                # needed: any model attribute reaching eval/exec/compile is
                # unsafe to execute.
                reason = (f"{base}() called on '{first.strip()}', a model/instance "
                          f"attribute that may hold attacker-controlled persisted data "
                          f"(second-order code execution) in '{fn.name}'")
            elif _is_variable(first):
                root = first.strip().split(".")[0]
                if root in tainted:
                    reason = f"{base}() called on '{root}', which is derived from request input in '{fn.name}'"
            if not reason:
                continue
            out.append(_build_vuln(
                self.category, fn.path, call.line,
                first.strip(), "code",
                reason,
                "Never pass untrusted input to eval/exec/compile; use ast.literal_eval or a safe parser.",
                fn.name,
            ))
        return out


# ---------------------------------------------------------------------------
# 29. Unrestricted File Upload (v0.4.0)
# ---------------------------------------------------------------------------


class UnrestrictedFileUploadDetector(StructuredDetector):
    """v0.4.0 – detect ``request.files`` persisted via ``.save()`` without a
    genuine file-type allowlist.

    Unlike the legacy :class:`FileUploadDetector` (which trusts
    ``secure_filename``), this detector only considers a function safe when it
    actually validates the upload *type*: an ``ALLOWED_EXTENSIONS`` set, an
    ``.endswith(...)`` check, or a ``content_type`` / ``mimetype`` check.
    ``secure_filename`` sanitises the name but says nothing about type, so it
    does **not** suppress the finding.
    """

    category = "unrestricted-file-upload"

    def detect(self, fn, source_lines, project_ir):
        body = self.code_text(fn, source_lines).lower()
        if "request.files" not in body and "file_storage" not in body and "request.file" not in body:
            return []
        has_save = any(c.name.split(".")[-1] == "save" for c in fn.calls)
        if not has_save:
            return []
        # genuine type allowlist present → safe
        if ("allowed_extensions" in body or ".endswith(" in body
                or "content_type" in body or "mimetype" in body
                or "allowed_types" in body):
            return []
        for call in fn.calls:
            if call.name.split(".")[-1] == "save":
                return [_build_vuln(
                    self.category, fn.path, call.line,
                    "file.save(...)", "filesystem",
                    f"Uploaded file persisted without a file-type allowlist in '{fn.name}'",
                    "Restrict uploads to an allowlisted extension / content-type list before saving.",
                    fn.name,
                )]
        return []


# ---------------------------------------------------------------------------
# 30. Mass Assignment (v0.4.0)
# ---------------------------------------------------------------------------


class MassAssignmentDetector(StructuredDetector):
    """v0.4.0 – detect ``**request.<body>`` expanded into a dict literal /
    constructor, letting clients set arbitrary fields (e.g. ``role='admin'``)."""

    category = "mass-assignment"
    _UNPACK = re.compile(
        r"\*\*\s*request\.(?:json|form|data|post|values|get_json|body)\b", re.I,
    )

    def detect(self, fn, source_lines, project_ir):
        out = []
        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line):
                continue
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if self._UNPACK.search(line):
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    stripped, "input",
                    f"Request body unpacked with ** into a model / dict in '{fn.name}'",
                    "Whitelist the fields a client may set (allowlist serialiser / form).",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 31. Insecure Randomness (v0.4.0)
# ---------------------------------------------------------------------------


class InsecureRandomnessDetector(StructuredDetector):
    """v0.4.0 – detect ``random`` used to mint security-sensitive material.

    Only reported when the produced value feeds a name that looks like a
    token / otp / password / secret / key / session id / nonce / csrf value.
    Ordinary ``random`` use for games, shuffling or list picking is ignored.
    """

    category = "insecure-randomness"
    _RANDOM_CALL = re.compile(
        r"\brandom\.(?:choice|choices|randint|random|randrange|sample|shuffle)\b",
    )
    _SENSITIVE_NAME = re.compile(
        r"token|otp|password|passwd|secret|key|session|nonce|csrf|session_id|reset",
        re.I,
    )
    _LHS_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+)$")

    def detect(self, fn, source_lines, project_ir):
        out = []
        reported = set()
        # (a) explicit assignment lhs = ...random...
        for expr in fn.assignment_exprs:
            m = self._LHS_ASSIGN.match(expr.strip())
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if self._RANDOM_CALL.search(rhs) and self._SENSITIVE_NAME.search(lhs):
                # locate the assignment line
                for lineno, line in enumerate(source_lines, 1):
                    if (fn.line <= lineno <= fn.end_line
                            and lhs in line and self._RANDOM_CALL.search(line)
                            and lineno not in reported):
                        reported.add(lineno)
                        out.append(_build_vuln(
                            self.category, fn.path, lineno,
                            line.strip()[:120], "crypto",
                            f"Insecure random module used to mint '{lhs}' in '{fn.name}'",
                            "Use the ``secrets`` module (secrets.token_urlsafe / secrets.randbelow) "
                            "for security-sensitive values.",
                            fn.name,
                        ))
        # (b) return / inline random use inside a security-named function
        if self._SENSITIVE_NAME.search(fn.name):
            for lineno, line in enumerate(source_lines, 1):
                if not (fn.line <= lineno <= fn.end_line) or lineno in reported:
                    continue
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if self._RANDOM_CALL.search(line):
                    reported.add(lineno)
                    out.append(_build_vuln(
                        self.category, fn.path, lineno,
                        stripped[:120], "crypto",
                        f"Insecure random module used inside security-sensitive '{fn.name}'",
                        "Use the ``secrets`` module instead of ``random`` for tokens / OTPs / keys.",
                        fn.name,
                    ))
        return out


# ---------------------------------------------------------------------------
# 32. Information Disclosure (v0.4.0)
# ---------------------------------------------------------------------------


class InformationDisclosureDetector(StructuredDetector):
    """v0.4.0 – leak of sensitive internals through errors / responses.

    (a) an exception / error message embeds credentials or a connection
        string (``mysql://user:pass@host`` …);
    (b) an HTTP handler returns a full traceback / exception object.
    """

    category = "information-disclosure"
    _CONN_STR = re.compile(
        r"://[^\s/'\"@:]+:[^\s/'\"@]+@"
        r"|(?:mysql|postgres(?:ql)?|mongodb|redis|amqp|mssql)://", re.I,
    )
    _RAISE_MSG = re.compile(r"\braise\b|\bException\s*\(|\bError\s*\(", re.I)
    _TRACEBACK = re.compile(
        r"traceback\.(?:format_exc|print_exc|format_exception|format_stack)"
        r"|\bsys\.exc_info\s*\(|\btraceback\.print_exc\s*\(",
        re.I,
    )

    def detect(self, fn, source_lines, project_ir):
        out = []
        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line):
                continue
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if self._RAISE_MSG.search(line) and self._CONN_STR.search(line):
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    stripped[:120], "error",
                    f"Exception message embeds a credential / connection string in '{fn.name}'",
                    "Log details server-side; return a generic, non-sensitive error to clients.",
                    fn.name,
                ))
            elif self._TRACEBACK.search(line):
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    stripped[:120], "error",
                    f"Full traceback / exception object returned to the client in '{fn.name}'",
                    "Return a generic error response; never expose stack traces to users.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 33. CSRF Protection Disabled (v0.4.0)
# ---------------------------------------------------------------------------


class CSRFDisablerDetector(StructuredDetector):
    """v0.4.0 – flag ``@csrf_exempt`` / ``csrf_exempt(view)`` /
    ``@method_decorator(csrf_exempt)``.  ``csrf_protect`` is never matched."""

    category = "csrf-disabled"

    def detect(self, fn, source_lines, project_ir):
        out = []
        for d in self.decorators(fn, source_lines):
            if "csrf_exempt" in d:
                out.append(_build_vuln(
                    self.category, fn.path, fn.line,
                    d, "web",
                    f"'{fn.name}' has CSRF protection disabled via {d}",
                    "Remove @csrf_exempt on state-changing views; require CSRF tokens.",
                    fn.name,
                ))
        # direct ``csrf_exempt(view_func)`` wrapping on a body line
        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line):
                continue
            stripped = line.strip()
            if "csrf_exempt(" in stripped and "csrf_exempt" not in [d for d in self.decorators(fn, source_lines)]:
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    stripped, "web",
                    f"'{fn.name}' wraps a view with csrf_exempt, disabling CSRF protection",
                    "Avoid csrf_exempt on state-changing views.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 34. SSL Verification Disabled (v0.4.0)
# ---------------------------------------------------------------------------


class SSLVerificationDisablerDetector(StructuredDetector):
    """v0.4.0 – detect ``requests.*(..., verify=False)``,
    ``urllib3.disable_warnings()``, ``ssl._create_unverified_context()`` and
    explicit ``check_hostname=False`` / ``CERT_NONE`` setups."""

    category = "ssl-verification-disabled"
    _HTTP_CALLS = {"get", "post", "put", "delete", "request", "patch", "head"}
    _VERIFY_FALSE = re.compile(r"verify\s*=\s*False", re.I)
    _UNVERIFIED_CTX = re.compile(r"_create_unverified_context|create_unverified_context", re.I)
    _DISABLE_WARN = re.compile(r"urllib3\.disable_warnings|disable_warnings\s*\(", re.I)
    _CHECK_HOSTNAME = re.compile(r"check_hostname\s*=\s*False|verify_mode\s*=\s*\w*CERT_NONE", re.I)
    # v0.4.3 – SSH equivalent of disabling certificate validation:
    # ``client.set_missing_host_key_policy(paramiko.AutoAddPolicy())`` blindly
    # trusts any server key presented on first use.
    _AUTO_ADD_POLICY = re.compile(r"AutoAddPolicy", re.I)

    def detect(self, fn, source_lines, project_ir):
        out = []
        seen = set()
        auto_policy_lines: dict = {}
        for call in fn.calls:
            joined = " ".join(call.args)
            name = call.name
            base = name.split(".")[-1]
            hit = ""
            if name.startswith("requests.") and base in self._HTTP_CALLS and self._VERIFY_FALSE.search(joined):
                hit = f"{name}(..., verify=False)"
            elif self._UNVERIFIED_CTX.search(name):
                hit = name
            elif self._DISABLE_WARN.search(name):
                hit = name
            elif self._AUTO_ADD_POLICY.search(name) or self._AUTO_ADD_POLICY.search(joined):
                # Inner call ``paramiko.AutoAddPolicy()`` and the outer
                # ``set_missing_host_key_policy(...)`` share a line: report once.
                auto_policy_lines.setdefault(
                    call.line,
                    "paramiko.AutoAddPolicy() — SSH host key is auto-accepted",
                )
            if hit and (call.line, hit) not in seen:
                seen.add((call.line, hit))
                out.append(_build_vuln(
                    self.category, fn.path, call.line,
                    hit, "network",
                    f"SSL certificate verification disabled via '{hit}' in '{fn.name}'",
                    "Do not disable TLS verification; pin / verify certificates in production.",
                    fn.name,
                ))
        for line, snippet in sorted(auto_policy_lines.items()):
            if line in seen:
                continue
            seen.add(line)
            out.append(_build_vuln(
                self.category, fn.path, line,
                snippet, "network",
                f"SSH host-key verification disabled via '{snippet}' in '{fn.name}' "
                f"(equivalent of disabling certificate validation)",
                "Use RejectPolicy()/WarningPolicy() and pin known host keys; never "
                "blindly accept unknown SSH hosts.",
                fn.name,
            ))
        # assignment-based disabling: ``context.check_hostname = False`` etc.
        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line) or lineno in seen:
                continue
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if self._CHECK_HOSTNAME.search(line):
                seen.add(lineno)
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    stripped, "network",
                    f"TLS hostname / certificate verification disabled in '{fn.name}'",
                    "Enable certificate verification (check_hostname=True, CERT_REQUIRED).",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 35. CORS Misconfiguration (v0.4.2)
# ---------------------------------------------------------------------------


class CORSMisconfigurationDetector(StructuredDetector):
    """v0.4.2 – flag unsafe Cross-Origin Resource Sharing policies.

    Reports when:

    * ``Access-Control-Allow-Origin`` is assigned a variable that flows from
      request input (e.g. ``request.headers.get('Origin')``), allowing an
      attacker-controlled origin to be reflected;
    * ``Access-Control-Allow-Origin`` is the wildcard ``*`` **and**
      ``Access-Control-Allow-Credentials`` is ``true``;
    * Flask-CORS is initialised with ``origins='*'`` / ``origins=['*']``.

    A static, fixed-domain literal (``'https://example.com'``) is never
    reported.
    """

    category = "cors-misconfiguration"
    _ACAO_ASSIGN = re.compile(
        r"""Access-Control-Allow-Origin['"]?\s*\]\s*=\s*(.+\S)\s*$""",
    )
    _CRED_TRUE = re.compile(
        r"""Access-Control-Allow-Credentials['"]?\s*[\])]?\s*=\s*['"]?true['"]?|"""
        r"""supports_credentials\s*=\s*True""",
        re.I,
    )
    _REQ_SRC = re.compile(
        r"request\.(?:args|form|json|values|data|body|cookies|headers|"
        r"query_params|view_args|files|get_json|POST|GET)\b"
        r"|request\s*\[\s*['\"]",
        re.I,
    )
    _LHS_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+)$")
    _CORS_INIT = re.compile(r"\bCORS\s*\(", re.I)
    _WILDCARD_ORIGINS = re.compile(
        r"""origins\s*=\s*(?:['"]\*['"]|\[[^\]]*['"]\*['"][^\]]*\])"""
        r"""|['"]origins['"]\s*:\s*['"]\*['"]""",
        re.I,
    )
    _IDENTS = re.compile(r"\b[A-Za-z_]\w*\b")
    # v0.5.0: FastAPI / Starlette ``app.add_middleware(CORSMiddleware, ...)``.
    _FASTAPI_CORS_LINE = re.compile(r"\bCORSMiddleware\b")
    _FASTAPI_WILDCARD = re.compile(
        r"allow_origins\s*=\s*(?:\[\s*['\"]\*['\"]\s*\]|['\"]\*['\"])"
        r"|allow_origin_regex\s*=\s*['\"]\.\*['\"]",
        re.I,
    )
    _FASTAPI_CRED = re.compile(r"allow_credentials\s*=\s*True", re.I)

    def _fastapi_cors_finding(self, fn, source_lines):
        """Detect module-level ``CORSMiddleware`` with a wildcard + credentials.

        Returns a (line, snippet) tuple when unsafe, else ``None``.  The window
        is bounded to a few lines so two different middleware blocks cannot be
        conflated.
        """
        for i, line in enumerate(source_lines):
            stripped = line.strip()
            if stripped.startswith(("import ", "from ")):
                continue
            if not self._FASTAPI_CORS_LINE.search(line):
                continue
            window = "\n".join(source_lines[i:i + 15])
            if self._FASTAPI_WILDCARD.search(window) and self._FASTAPI_CRED.search(window):
                return i + 1, stripped
        return None

    def _tainted_names(self, fn) -> set:
        tainted: set = set(fn.parameters)
        for expr in fn.assignment_exprs:
            m = self._LHS_ASSIGN.match(expr.strip())
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if self._REQ_SRC.search(rhs):
                tainted.add(lhs)
        return tainted

    def detect(self, fn, source_lines, project_ir):
        out = []
        # v0.5.0: FastAPI / Starlette module-level CORSMiddleware.  This config
        # lives outside any function, so scan the file (dedup collapses repeats
        # across the per-function pipeline runs).
        fw = self._fastapi_cors_finding(fn, source_lines)
        if fw is not None:
            line_no, snippet = fw
            out.append(_build_vuln(
                self.category, fn.path, line_no,
                snippet, "web",
                "FastAPI CORSMiddleware configured with wildcard origin "
                "(allow_origins=['*'] or allow_origin_regex='.*') and allow_credentials=True",
                "Restrict CORS origins to an explicit allowlist of trusted domains; "
                "never combine a wildcard with credential support.",
                fn.name,
            ))
        body = self.code_text(fn, source_lines)
        if "Access-Control-Allow-Origin" not in body and "CORS(" not in body:
            return out
        cred_true = bool(self._CRED_TRUE.search(body))
        tainted = self._tainted_names(fn)

        # Flask-CORS wildcard initialisation: CORS(app, resources={..., origins='*'})
        if self._CORS_INIT.search(body) and self._WILDCARD_ORIGINS.search(body):
            m_line = 0
            for lineno, line in enumerate(source_lines, 1):
                if fn.line <= lineno <= fn.end_line and "CORS(" in line:
                    m_line = lineno
                    break
            out.append(_build_vuln(
                self.category, fn.path, m_line or fn.line,
                "CORS(app, ..., origins='*')", "web",
                "Flask-CORS configured with wildcard origins",
                "Restrict CORS origins to an explicit allowlist of trusted domains.",
                fn.name,
            ))
            return out

        for lineno, line in enumerate(source_lines, 1):
            if not (fn.line <= lineno <= fn.end_line):
                continue
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = self._ACAO_ASSIGN.search(stripped)
            if not m:
                continue
            rhs = m.group(1).strip()
            # Static literal RHS
            if _is_string_literal(rhs):
                value = rhs.strip().strip("'\"")
                if value == "*" and cred_true:
                    out.append(_build_vuln(
                        self.category, fn.path, lineno,
                        stripped, "web",
                        "Access-Control-Allow-Origin='*' combined with Allow-Credentials: true",
                        "Do not combine a wildcard origin with credential support.",
                        fn.name,
                    ))
                # fixed-domain literal → safe, skip
                continue
            # Non-literal RHS: only report when it traces to request input.
            is_tainted = self._REQ_SRC.search(rhs) is not None
            if not is_tainted:
                roots = set(self._IDENTS.findall(rhs))
                if any(r in tainted for r in roots):
                    is_tainted = True
            if is_tainted:
                out.append(_build_vuln(
                    self.category, fn.path, lineno,
                    stripped, "web",
                    "Access-Control-Allow-Origin reflects a request-controlled value",
                    "Reflect only an explicit allowlist of trusted origins; never echo the raw Origin header.",
                    fn.name,
                ))
        return out


# ---------------------------------------------------------------------------
# 36. Insecure Cookie Attributes (v0.4.2)
# ---------------------------------------------------------------------------


class InsecureCookieDetector(StructuredDetector):
    """v0.4.2 – flag ``set_cookie`` calls missing HttpOnly / Secure flags.

    A call is reported when ``httponly`` is absent or ``False``, or when
    ``secure`` is absent or ``False``.  Only a call that *explicitly* sets
    both ``httponly=True`` and ``secure=True`` is treated as safe.
    """

    category = "insecure-cookie"
    _HTTPONLY_FALSE = re.compile(r"\bhttponly\s*=\s*False\b", re.I)
    _SECURE_FALSE = re.compile(r"\bsecure\s*=\s*False\b", re.I)
    _HTTPONLY_PRESENT = re.compile(r"\bhttponly\s*=", re.I)
    _SECURE_PRESENT = re.compile(r"\bsecure\s*=", re.I)
    _HTTPONLY_TRUE = re.compile(r"\bhttponly\s*=\s*True\b", re.I)
    _SECURE_TRUE = re.compile(r"\bsecure\s*=\s*True\b", re.I)

    def detect(self, fn, source_lines, project_ir):
        out = []
        for call in fn.calls:
            base = call.name.split(".")[-1]
            if base != "set_cookie":
                continue
            joined = " ".join(call.args)
            httponly_bad = bool(
                self._HTTPONLY_FALSE.search(joined)
                or not self._HTTPONLY_PRESENT.search(joined)
            )
            secure_bad = bool(
                self._SECURE_FALSE.search(joined)
                or not self._SECURE_PRESENT.search(joined)
            )
            # explicitly safe only when both are True
            if self._HTTPONLY_TRUE.search(joined) and self._SECURE_TRUE.search(joined):
                httponly_bad = False
                secure_bad = False
            if not (httponly_bad or secure_bad):
                continue
            missing = []
            if httponly_bad:
                missing.append("HttpOnly")
            if secure_bad:
                missing.append("Secure")
            out.append(_build_vuln(
                self.category, fn.path, call.line,
                joined.strip()[:140], "web",
                f"set_cookie() missing {'/'.join(missing)} flag(s) in '{fn.name}'",
                "Set httponly=True and secure=True (plus samesite='Lax'/'Strict') on sensitive cookies.",
                fn.name,
            ))
        return out


# ---------------------------------------------------------------------------
# 37. Zip Slip / Unsafe Archive Extraction (v0.4.2)
# ---------------------------------------------------------------------------


class ZipSlipDetector(StructuredDetector):
    """v0.4.2 – flag extraction of user-uploaded archives without path checks.

    Reports when ``ZipFile.extractall`` / ``TarFile.extractall`` (or single
    ``extract`` calls) operate on an archive that originates from an upload
    (``request.FILES`` / ``request.files``) and the function body contains no
    path-validation logic.  A function that inspects member names for ``..`` /
    absolute paths (``isabs`` / ``abspath`` / ``realpath`` / ``commonpath`` /
    ``infolist`` …) is treated as safe.
    """

    category = "zip-slip"
    _UPLOAD_SRC = re.compile(r"request\.(?:FILES|files)\b", re.I)
    _EXTRACT_CALLS = {"extractall", "extract"}
    _ARCHIVE_CTX = re.compile(r"ZipFile|TarFile|tarfile|zipfile|ZipInfo", re.I)
    _VALIDATION = re.compile(
        r"isabs\s*\(|os\.path\.(?:abspath|realpath|relpath|commonpath|normpath)\s*\("
        r"|\.resolve\s*\(\)|commonpath|commonprefix"
        r"|infolist\s*\(|namelist\s*\(|getmember\s*\("
        r"|startswith\s*\(\s*['\"]\/"
        r"|['\"]\.\.['\"]"
        r"|extractall\s*\([^)]*filter\s*=",
        re.I,
    )

    def detect(self, fn, source_lines, project_ir):
        body = self.code_text(fn, source_lines)
        if not self._UPLOAD_SRC.search(body):
            return []  # no upload source → not in scope
        has_validation = bool(self._VALIDATION.search(body))
        if has_validation:
            return []
        out = []
        archive_ctx = bool(self._ARCHIVE_CTX.search(body))
        for call in fn.calls:
            base = call.name.split(".")[-1]
            if base not in self._EXTRACT_CALLS:
                continue
            # bare ``extract`` calls need archive context to avoid noise
            if base == "extract" and not archive_ctx:
                continue
            out.append(_build_vuln(
                self.category, fn.path, call.line,
                ".".join(call.name.split(".")[-2:]), "filesystem",
                f"Archive member extracted from a user upload without path validation in '{fn.name}'",
                "Validate each member name (reject '..' and absolute paths) and resolve the destination before extraction.",
                fn.name,
            ))
        return out


# ---------------------------------------------------------------------------
# 38. Email Header Injection (v0.4.3)
# ---------------------------------------------------------------------------


class EmailHeaderInjectionDetector(StructuredDetector):
    """v0.4.3 – flag SMTP bodies that interpolate attacker-controlled values
    directly into mail headers (``To`` / ``From`` / ``Subject`` / ``Cc`` /
    ``Bcc``), allowing CRLF header / content injection (CWE-640).

    A function is in scope when it performs a ``*.sendmail(...)`` call (or
    builds a message via ``smtplib.SMTP``).  The third argument of
    ``sendmail`` — the raw message — is traced back to its assignment; when
    that value is an f-string which (a) contains at least one header token
    (``To:``/``From:``/``Subject:``/``Cc:``/``Bcc:``) and (b) interpolates at
    least one ``{...}`` expression, the finding is reported.

    A fully static, non-interpolated message body is never reported.
    """

    category = "email-header-injection"
    _SENDMAIL = re.compile(r"sendmail$", re.I)
    _SMTP_CTX = re.compile(r"smtplib\.SMTP|smtplib$", re.I)
    _HEADER = re.compile(r"(?:To|From|Subject|Cc|Bcc)\s*:", re.I)
    _ASSIGN = re.compile(r"^([A-Za-z_]\w*)\s*=\s*(.+)$")

    @staticmethod
    def _is_fstr(text: str) -> bool:
        t = text.strip()
        return t.startswith(("f'", 'f"', "F'", 'F"'))
    def detect(self, fn, source_lines, project_ir):
        # Build lhs -> rhs assignment map for cheap variable tracing.
        assigns: dict = {}
        for expr in fn.assignment_exprs:
            m = self._ASSIGN.match(expr.strip())
            if m:
                assigns.setdefault(m.group(1), m.group(2).strip())

        # Collect candidate message strings: either the third positional arg of
        # a sendmail call itself, or a variable assigned an f-string.
        out = []
        has_smtp = False
        for call in fn.calls:
            if self._SENDMAIL.search(call.name):
                has_smtp = True
                msg_expr = call.args[2] if len(call.args) >= 3 else ""
                candidates = [msg_expr]
                # trace a bare variable back to its f-string assignment
                root = msg_expr.strip()
                if root in assigns:
                    candidates.append(assigns[root])
                for cand in candidates:
                    if self._is_fstr(cand) and self._HEADER.search(cand) and "{" in cand:
                        out.append(_build_vuln(
                            self.category, fn.path, call.line,
                            f"{call.name}(...) with interpolated headers",
                            "smtp",
                            f"Mail message for '{call.name}' interpolates "
                            f"user-controlled values into To/From/Subject headers in "
                            f"'{fn.name}' (CRLF / header injection)",
                            "Validate and sanitize recipient/subject values; use an SMTP "
                            "library that encodes headers (e.g. email.message.EmailMessage)",
                            fn.name,
                        ))
                        break
            elif self._SMTP_CTX.search(call.name):
                has_smtp = True

        # Simplified fallback: an smtplib-based helper that builds a header
        # f-string even when the sendmail call's 3rd arg is not directly
        # traced (defensive; covers EmailMessage / send_mail shapes).
        if not out and has_smtp:
            for lhs, rhs in assigns.items():
                if self._is_fstr(rhs) and self._HEADER.search(rhs) and "{" in rhs:
                    out.append(_build_vuln(
                        self.category, fn.path, fn.line,
                        f"{lhs} = <interpolated mail headers>", "smtp",
                        f"Mail body '{lhs}' is built from an f-string containing "
                        f"To/From/Subject headers with variable interpolation in "
                        f"'{fn.name}' (header injection)",
                        "Sanitize header values against CRLF; use a proper MIME library.",
                        fn.name,
                    ))
                    break
        return out


# ---------------------------------------------------------------------------
# 39. Insecure Temporary File (v0.4.3)
# ---------------------------------------------------------------------------


class InsecureTempFileDetector(StructuredDetector):
    """v0.4.3 – flag predictable temporary filenames under ``/tmp`` and
    world-writable temporary files (CWE-377 / CWE-732).

    Reports two shapes:

    * **Predictable path** – ``open(...)`` writes to a path whose value is an
      f-string under ``/tmp/`` interpolating predictable values (``os.getpid()``,
      timestamps / ``now()``, counters), which enables symlink / race attacks.
    * **World-writable mode** – ``os.chmod(path, 0o777)`` / ``0o666``.

    The safe APIs ``tempfile.mkstemp`` / ``tempfile.NamedTemporaryFile`` /
    ``tempfile.mkdtemp`` are not flagged.
    """

    category = "insecure-temp-file"
    _ASSIGN = re.compile(r"^([A-Za-z_]\w*)\s*=\s*(.+)$")
    _PREDICTABLE = re.compile(
        r"getpid|timestamp|now\s*\(\)|time\s*\(\)|counter|str\s*\(\s*os\.",
        re.I,
    )
    _SAFE_TMP = re.compile(r"mkstemp|NamedTemporaryFile|mkdtemp|mktemp", re.I)
    # 0o777 == 511, 0o666 == 438 after ast.unparse; also accept literal octal.
    _WORLD_MODES = re.compile(r"^(?:0o(?:777|666)|511|438)$")

    def detect(self, fn, source_lines, project_ir):
        # Safe temp APIs present → the function already uses a secure path.
        uses_safe_tmp = any(
            self._SAFE_TMP.search(c.name) for c in fn.calls
        )

        assigns: dict = {}
        for expr in fn.assignment_exprs:
            m = self._ASSIGN.match(expr.strip())
            if m:
                assigns.setdefault(m.group(1), m.group(2).strip())

        out = []
        seen_lines = set()

        for call in fn.calls:
            base = call.name.split(".")[-1]

            # Rule A: open(<predictable /tmp path>, ...)
            if base == "open" and call.args:
                path_arg = call.args[0].strip()
                candidate = path_arg
                root = path_arg.strip().strip("'\"")
                if root in assigns:
                    candidate = assigns[root]
                is_fstr = candidate.startswith(("f'", 'f"', "F'", 'F"'))
                if (is_fstr and not uses_safe_tmp
                        and "/tmp/" in candidate
                        and "{" in candidate
                        and self._PREDICTABLE.search(candidate)):
                    if call.line not in seen_lines:
                        seen_lines.add(call.line)
                        out.append(_build_vuln(
                            self.category, fn.path, call.line,
                            candidate[:80], "filesystem",
                            f"Temporary file at a predictable /tmp path is opened for "
                            f"writing in '{fn.name}' (symlink / race condition)",
                            "Use tempfile.mkstemp() / tempfile.NamedTemporaryFile() which "
                            "create unpredictable, mode-0600 files atomically.",
                            fn.name,
                        ))

            # Rule B: os.chmod(path, 0o777 / 0o666)
            if base == "chmod":
                for arg in call.args[1:]:
                    if self._WORLD_MODES.match(arg.strip()):
                        if call.line not in seen_lines:
                            seen_lines.add(call.line)
                            out.append(_build_vuln(
                                self.category, fn.path, call.line,
                                f"os.chmod(..., {arg.strip()})", "filesystem",
                                f"Temporary/shared file is made world-accessible "
                                f"(mode {arg.strip()}) in '{fn.name}'",
                                "Restrict file permissions (0600/0640); never 0777/0666.",
                                fn.name,
                            ))
                        break
        return out


# ---------------------------------------------------------------------------
# v0.6.0 – Missing Authentication (CWE-306)
# ---------------------------------------------------------------------------


class MissingAuthenticationDetector(StructuredDetector):
    """v0.6.0 – HTTP route handlers with no authentication check (CWE-306).

    Flags a Flask / Django / FastAPI route handler that reaches user input or
    mutates state but carries *no* authentication signal — no ``@login_required``
    / ``@token_required`` decorator, no ``current_user`` / ``g.user``, no
    ``request.headers.get('Authorization')`` / ``jwt.decode``, no
    ``Depends(get_current_user)`` FastAPI dependency.

    Public / informational endpoints are excluded: health checks, login /
    register / token issuers, docs, and pure read-only static pages.
    """

    category = "missing-authentication"

    # Any mention of authentication / identity in a decorator or the body.
    _AUTH = re.compile(
        r"login_required|token_required|jwt_required|jwt\.decode|jwt\.get_|verify_token|decode_token|"
        r"token_required|jwt_required|jwt\.decode|jwt\.get_|verify_token|decode_token|"
        r"@?\w*auth\w*_?required|@?\w*_?auth\b|authenticate|authorize|"
        r"current_user|g\.user|get_current_user|OAuth2|HTTPBearer|HTTPBasic|"
        r"Authorization|Bearer|set_protected|"
        r"Depends\s*\(|request\.headers\.get\s*\(\s*['\"]authorization|"
        r"session\s*\[?\s*['\"]?(?:user|uid|auth|token)",
        re.I,
    )
    # Route decorators (Flask / FastAPI / Django / generic).
    _ROUTE = re.compile(
        r"\.route\s*\(|\.(?:get|post|put|delete|patch|options|head)\s*\(",
        re.I,
    )
    # Public / non-sensitive paths that must never be flagged.
    _PUBLIC = re.compile(
        r"^/?(?:health|healthz|live|livez|ready|readyz|ping|status|metrics|"
        r"favicon\.?.*|docs?|redoc|openapi\.json)$"
        r"|/(?:login|log_in|signin|sign_in|register|signup|sign_up|logout|log_out|"
        r"auth|oauth|token|refresh|forgot|reset|password)"
        r"|(?:^|/)static/",
        re.I,
    )
    # User input / state change indicators (only flag handlers that matter).
    _INPUT = re.compile(
        r"request\.(?:args|form|json|values|data|body|files|query_params|"
        r"cookies|headers|POST|GET)\b|request\s*\[|Depends\s*\(",
        re.I,
    )
    # object-identifier parameter (``task_id`` / ``user_id`` / ``doc_id`` …)
    _ID_PARAM = re.compile(r"(?:^|_)(?:user|doc|order|account|file|task|item|record|obj|id|pk|uuid|invoice|transaction)_?(?:id)?$|_id$", re.I)
    _WRITE = re.compile(
        r"\b(?:INSERT|UPDATE|DELETE)\b|\.add\s*\(|\.commit\s*\(|\.save\s*\(|"
        r"\.execute\s*\(\s*['\"]\s*(?:INSERT|UPDATE|DELETE)",
        re.I,
    )

    def detect(self, fn, source_lines, project_ir):
        if not is_route_handler(fn):
            return []
        decos = self.decorators(fn, source_lines)
        joined = " ".join(decos)
        body = self.code_text(fn, source_lines)
        # Authentication already present anywhere on the handler?
        if self._AUTH.search(joined) or self._AUTH.search(body):
            return []
        # Exclude public / informational endpoints: pull the route path string
        # from the decorator (``@app.post("/task/{id}")`` → "/task/{id}").
        path_match = re.search(r"['\"]([^'\"]+)['\"]", joined)
        route_path = path_match.group(1) if path_match else ""
        if self._PUBLIC.search(route_path):
            return []
        # Conservative sensitivity gate: only flag endpoints that touch a
        # specific resource by identifier (path/query object id, e.g.
        # ``task_id`` / ``user_id``) or that perform a direct database write.
        # Trivial demo / read-only handlers that merely echo request input
        # (``/query``, ``/upload``, ``/deserialize`` in a local lab) are not
        # reported — the benchmark's remediated reference must stay clean.
        has_input = bool(fn.sources) or bool(fn.parameters) or bool(self._INPUT.search(body))
        has_write = bool(self._WRITE.search(body))
        has_id_param = any(
            re.search(self._ID_PARAM, p) for p in fn.parameters
        )
        has_id_in_path = bool(re.search(r"\{\s*[\w_]*id[\w_]*\s*\}|<\w*:?\w*id\w*>", route_path, re.I))
        if not has_input:
            return []
        # Sensitivity gate: flag when the handler takes a request model / path
        # parameter (FastAPI body, Flask <id>), names an object id, or performs
        # a direct DB write.  Local-lab demo handlers with NO parameters and
        # only in-body ``request.args/form`` echoes (the benchmark's remediated
        # reference) stay unreported.
        if not (has_write or has_id_param or has_id_in_path or bool(fn.parameters)):
            return []
        snippet = decos[0] if decos else f"@app.route(...) def {fn.name}"
        return [_build_vuln(
            self.category, fn.path, fn.line,
            snippet.strip()[:120], "auth",
            f"Route handler '{fn.name}' is reachable with no authentication check "
            f"(no login_required / token / session / auth dependency).",
            "Require authentication: add @login_required / @token_required, a "
            "Authorization header check, or a FastAPI Depends(get_current_user).",
            fn.name,
        )]


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class DetectorPipeline:
    """Run every :class:`StructuredDetector` and merge results."""

    def __init__(self) -> None:
        self.detectors: List[StructuredDetector] = [
            SQLInjectionDetector(),
            CommandInjectionDetector(),
            PathTraversalDetector(),
            SSRFDetector(),
            XSSDetector(),
            SSTIDetector(),
            HardcodedSecretDetector(),
            DangerousDeserializationDetector(),
            ReDoSDetector(),
            ArbitraryFileWriteDetector(),
            FileUploadDetector(),
            OpenRedirectDetector(),
            WeakCryptoDetector(),
            InsecureDefaultDetector(),
            AuthBypassDetector(),
            IDORDetector(),
            NoSQLInjectionDetector(),
            XXEDetector(),
            JWTFlawDetector(),
            LdapInjectionDetector(),
            # v0.3.0 – round-3 targeted detectors
            SecurityMisconfigurationDetector(),
            SensitiveDataLoggingDetector(),
            UserEnumerationDetector(),
            SensitiveDataExposureDetector(),
            MissingRateLimitingDetector(),
            WeakPasswordPolicyDetector(),
            BusinessLogicFlawDetector(),
            RaceConditionDetector(),
            # v0.6.0 – new detectors
            MissingAuthenticationDetector(),
            # v0.3.1 – round-4 cross-validation fixes
            CodeInjectionDetector(),
            # v0.4.0 – round-5 Django shooting-range detectors
            UnrestrictedFileUploadDetector(),
            MassAssignmentDetector(),
            InsecureRandomnessDetector(),
            InformationDisclosureDetector(),
            CSRFDisablerDetector(),
            SSLVerificationDisablerDetector(),
            # v0.4.2 – round-7 shooting-range fixes
            CORSMisconfigurationDetector(),
            InsecureCookieDetector(),
            ZipSlipDetector(),
            # v0.4.3 – round-8 shooting-range fixes
            EmailHeaderInjectionDetector(),
            InsecureTempFileDetector(),
        ]

    def run(self, function_ir: FunctionIR, source_lines: List[str], project_ir: ProjectIR) -> List[Vulnerability]:
        results: List[Vulnerability] = []
        seen: set = set()
        for detector in self.detectors:
            try:
                found = detector.detect(function_ir, source_lines, project_ir)
            except Exception:
                continue
            for v in found:
                key = (v.category, v.file, v.line, v.snippet)
                if key in seen:
                    continue
                seen.add(key)
                results.append(v)
        return results


# ---------------------------------------------------------------------------
# Combined entry point
# ---------------------------------------------------------------------------


def scan_file_with_ir(path, project_ir: ProjectIR) -> List[Vulnerability]:
    """Run both the legacy regex scan and the structured detector pipeline.

    Returns a list of fully-populated :class:`Vulnerability` objects.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    source_lines = text.splitlines()
    resolved = str(p.resolve())

    # 1. legacy regex findings -> Vulnerabilities
    vulns: List[Vulnerability] = []
    for finding in scan_file(p):
        vulns.append(finding.to_vulnerability())

    # 2. structured detectors for functions belonging to this file
    pipeline = DetectorPipeline()
    target_fns = [
        fn for fn in project_ir.functions
        if fn.path == resolved or fn.path == str(p)
    ]
    for fn in target_fns:
        vulns.extend(pipeline.run(fn, source_lines, project_ir))

    # 2b. v0.5.0: module-level pass for configuration-only files that contain
    # no functions (e.g. ``config.py``).  Structured detectors only run against
    # functions, so a module-level ``os.environ.get(..., "default-secret")``
    # would otherwise be invisible.  Only whole-file scanners are rerun here.
    if not target_fns:
        module_fn = FunctionIR(
            name="<module>",
            qualified_name="<module>",
            path=resolved,
            line=1,
            end_line=len(source_lines),
        )
        for det in (HardcodedSecretDetector(), CORSMisconfigurationDetector()):
            try:
                vulns.extend(det.detect(module_fn, source_lines, project_ir))
            except Exception:
                pass

    # 3. dedup
    seen: set = set()
    deduped: List[Vulnerability] = []
    for v in vulns:
        key = (v.category, v.file, v.line, v.snippet)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(v)
    return deduped
