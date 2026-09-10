"""Structured security knowledge base (PHASE 3 / 4 / 5).

Provides:
* ``SOURCES`` – attacker-controllable entry points (HTTP / file / external / env)
* ``SINKS`` – dangerous operations grouped by category (SQL / command / file / …)
* ``VULN_CATEGORIES`` – full vulnerability category matrix with metadata
* ``SANITIZERS`` – known safe encoders / validators / parameterisers
* ``AUTH_PATTERNS`` – authentication & authorization function / decorator names
* ``FRAMEWORK_SIGNATURES`` – lightweight framework detection hints

All data is plain Python literals so the package stays dependency-free.
"""
from __future__ import annotations

from typing import Dict, List, Set


# ===================================================================
# PHASE 3 – Source library
# ===================================================================

SOURCES: Dict[str, Dict[str, List[str]]] = {
    "http": {
        "query": ["request.args", "request.query_params", "request.GET", "req.query", "ctx.query"],
        "path": ["request.view_args", "request.path_params", "req.params", "ctx.params"],
        "header": ["request.headers", "req.headers", "ctx.request.headers"],
        "cookie": ["request.cookies", "req.cookies", "ctx.cookies"],
        "body": ["request.data", "request.body", "req.body", "request.stream"],
        "multipart": ["request.files", "request.form", "req.multipart"],
        "json": ["request.json", "request.get_json", "req.json", "ctx.request.json"],
        "xml": ["request.xml", "body_xml"],
        "form": ["request.form", "request.POST", "req.form", "ctx.form"],
        "websocket": ["websocket.receive", "ws.recv", "socketio.on"],
    },
    "file": {
        "filename": ["filename", "file_name", "upload.filename"],
        "path": ["filepath", "file_path", "path_param", "user_path"],
        "archive": ["zipfile", "tarfile", "extract", "unpack"],
        "upload": ["request.files", "uploaded_file", "file_storage"],
        "import": ["__import__", "importlib", "import_module"],
        "configuration": ["config.load", "settings.from", "ini.read", "yaml.load"],
    },
    "external": {
        "database": ["db.query", "session.query", "cursor.execute", "orm.filter"],
        "redis": ["redis.get", "cache.get", "r.get"],
        "queue": ["queue.get", "consumer.poll", "mq.receive"],
        "webhook": ["webhook.payload", "hook.data"],
        "third_party_api": ["requests.get", "http.get", "client.request"],
        "message": ["message.body", "msg.payload", "event.data"],
    },
    "environment": {
        "environment_variable": ["os.environ", "os.getenv", "env.get", "process.env"],
        "cli_argument": ["sys.argv", "argparse", "click.option", "typer.Argument"],
        "configuration": ["config.get", "settings.", "app.config"],
        "system_property": ["sys.props", "property.get"],
    },
}

# Flat set of source token substrings for quick matching
SOURCE_TOKENS: Set[str] = set()
for _cat in SOURCES.values():
    for _tokens in _cat.values():
        SOURCE_TOKENS.update(_tokens)


# ===================================================================
# PHASE 4 – Dangerous Sink library (8 categories)
# ===================================================================

SINKS: Dict[str, Dict[str, List[str]]] = {
    "sql": {
        "raw_query": ["execute", "executemany", "raw", "query", "cursor.execute"],
        "string_concat": [],  # detected via f-string / + / .format in argument
        "dynamic_sql": ["db.session.execute", "connection.execute"],
        "orm_raw": ["raw", "extra", "RawSQL", "annotate(SQL("],
    },
    "command": {
        "system": ["os.system", "os.popen"],
        "exec": ["exec", "eval"],
        "spawn": ["subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "os.execvp"],
        "shell": ["shell=True", "/bin/sh", "bash -c"],
    },
    "file": {
        "open": ["open", "io.open", "codecs.open"],
        "read": ["read_text", "read_bytes", "Path.read"],
        "write": ["write_text", "write_bytes", "Path.write"],
        "rename": ["os.rename", "shutil.move"],
        "delete": ["os.remove", "os.unlink", "shutil.rmtree"],
        "extract": ["extractall", "extract", "TarFile.extract", "ZipFile.extract"],
    },
    "network": {
        "http_request": ["requests.get", "requests.post", "requests.put", "requests.delete", "requests.request"],
        "url_fetch": ["urllib.request.urlopen", "urllib.request.Request", "urlopen", "fetch"],
        "socket": ["socket.connect", "socket.send", "create_connection"],
        "proxy": ["proxies", "set_proxy"],
        "redirect": ["redirect", "HttpResponseRedirect", "redirect_url"],
    },
    "template": {
        "render": ["render_template_string", "Template(", "env.from_string"],
        "template": ["render_template", "Jinja2"],
        "expression_eval": ["eval", "compile", "expr("],
    },
    "serialization": {
        "deserialize": ["pickle.load", "pickle.loads", "cPickle.load", "marshal.loads"],
        "unmarshal": ["yaml.load", "xmltodict.parse", "toml.loads"],
        "decode": ["base64.b64decode", "json.loads"],
        "object_reconstruction": ["copy.deepcopy", "shelve.open"],
    },
    "browser": {
        "html": ["Markup(", "mark_safe", "format_html", "safe_join"],
        "js": ["javascript:", "onclick=", "eval("],
        "dom": ["innerHTML", "document.write", "element.html"],
        "redirect": ["window.location", "location.href", "redirect("],
    },
    "native_memory": {
        "memcpy": ["memcpy", "memmove"],
        "strcpy": ["strcpy", "strcat", "sprintf", "vsprintf"],
        "format": ["printf", "fprintf", "snprintf"],
        "pointer_arithmetic": ["ptr+", "ptr-", "*ptr"],
        "allocation": ["malloc", "calloc", "realloc", "new"],
        "free": ["free", "delete", "delete[]"],
    },
}

# Flat set of sink function names
SINK_FUNCTIONS: Set[str] = set()
for _cat in SINKS.values():
    for _names in _cat.values():
        SINK_FUNCTIONS.update(_names)


# ===================================================================
# PHASE 5 – Vulnerability category matrix
# ===================================================================

VULN_CATEGORIES: Dict[str, Dict[str, str]] = {
    # --- Web / API (13) ---
    "sql-injection": {"title": "SQL Injection", "group": "web-api", "default_severity": "High", "cwe": "CWE-89"},
    "nosql-injection": {"title": "NoSQL Injection", "group": "web-api", "default_severity": "High", "cwe": "CWE-943"},
    "command-injection": {"title": "Command Injection", "group": "web-api", "default_severity": "Critical", "cwe": "CWE-78"},
    # v0.3.1 – eval() / exec() / compile() on attacker-controlled input
    "code-injection": {"title": "Arbitrary Code Execution", "group": "web-api", "default_severity": "Critical", "cwe": "CWE-94"},
    "xss": {"title": "Cross-Site Scripting (XSS)", "group": "web-api", "default_severity": "Medium", "cwe": "CWE-79"},
    "ssti": {"title": "Server-Side Template Injection", "group": "web-api", "default_severity": "Critical", "cwe": "CWE-1336"},
    "ssrf": {"title": "Server-Side Request Forgery", "group": "web-api", "default_severity": "High", "cwe": "CWE-918"},
    "path-traversal": {"title": "Path Traversal", "group": "web-api", "default_severity": "High", "cwe": "CWE-22"},
    "arbitrary-file-read": {"title": "Arbitrary File Read", "group": "web-api", "default_severity": "High", "cwe": "CWE-22"},
    "arbitrary-file-write": {"title": "Arbitrary File Write", "group": "web-api", "default_severity": "Critical", "cwe": "CWE-73"},
    "file-upload": {"title": "Unrestricted File Upload", "group": "web-api", "default_severity": "High", "cwe": "CWE-434"},
    # v0.4.0 – round-5 Django shooting-range categories
    "unrestricted-file-upload": {"title": "Unrestricted File Upload", "group": "web-api", "default_severity": "High", "cwe": "CWE-434"},
    "mass-assignment": {"title": "Mass Assignment", "group": "web-api", "default_severity": "High", "cwe": "CWE-915"},
    "insecure-randomness": {"title": "Insecure Randomness", "group": "web-api", "default_severity": "Medium", "cwe": "CWE-330"},
    "information-disclosure": {"title": "Information Disclosure", "group": "web-api", "default_severity": "Medium", "cwe": "CWE-209"},
    "xxe": {"title": "XML External Entity", "group": "web-api", "default_severity": "High", "cwe": "CWE-611"},
    "ldap-injection": {"title": "LDAP Injection", "group": "web-api", "default_severity": "High", "cwe": "CWE-90"},
    "open-redirect": {"title": "Open Redirect", "group": "web-api", "default_severity": "Low", "cwe": "CWE-601"},
    "crlf-injection": {"title": "CRLF Injection", "group": "web-api", "default_severity": "Medium", "cwe": "CWE-93"},
    # v0.4.1 – round-6 shooting range: ReDoS (catastrophic backtracking)
    "redos": {"title": "Regular Expression Denial of Service", "group": "web-api", "default_severity": "Medium", "cwe": "CWE-1333"},
    # v0.4.2 – round-7 shooting range: CORS / cookie / archive-extraction misses
    "cors-misconfiguration": {"title": "CORS Misconfiguration", "group": "security-misconfiguration", "default_severity": "Medium", "cwe": "CWE-942"},
    "insecure-cookie": {"title": "Insecure Cookie Attributes", "group": "web-api", "default_severity": "Low", "cwe": "CWE-614"},
    "zip-slip": {"title": "Zip Slip / Path Traversal in Archive Extraction", "group": "web-api", "default_severity": "High", "cwe": "CWE-22"},
    # v0.3.0 – round-3 shooting-range detectors
    "sensitive-data-logging": {"title": "Sensitive Data in Logs", "group": "web-api", "default_severity": "Medium", "cwe": "CWE-532"},
    "sensitive-data-exposure": {"title": "Sensitive Data Exposure", "group": "web-api", "default_severity": "High", "cwe": "CWE-200"},

    # --- Authentication (10) ---
    "auth-bypass": {"title": "Authentication Bypass", "group": "authentication", "default_severity": "Critical", "cwe": "CWE-287"},
    # v0.6.0 – route handlers that reach user input / state-changing operations
    # with no authentication check at all (CWE-306).
    "missing-authentication": {"title": "Missing Authentication for Function", "group": "authentication", "default_severity": "Medium", "cwe": "CWE-306"},
    "session-fixation": {"title": "Session Fixation", "group": "authentication", "default_severity": "Medium", "cwe": "CWE-384"},
    "weak-session": {"title": "Weak Session Management", "group": "authentication", "default_severity": "Medium", "cwe": "CWE-330"},
    "jwt-flaws": {"title": "JWT Implementation Flaw", "group": "authentication", "default_severity": "High", "cwe": "CWE-347"},
    "oauth-flaws": {"title": "OAuth Implementation Flaw", "group": "authentication", "default_severity": "High", "cwe": "CWE-346"},
    "password-reset-flaws": {"title": "Password Reset Flaw", "group": "authentication", "default_severity": "High", "cwe": "CWE-640"},
    "mfa-bypass": {"title": "MFA Bypass", "group": "authentication", "default_severity": "High", "cwe": "CWE-308"},
    "account-recovery-flaws": {"title": "Account Recovery Flaw", "group": "authentication", "default_severity": "High", "cwe": "CWE-640"},
    # v0.3.0 – round-3 shooting-range detectors
    "user-enumeration": {"title": "User Enumeration", "group": "authentication", "default_severity": "Low", "cwe": "CWE-204"},
    "weak-password-policy": {"title": "Weak Password Policy", "group": "authentication", "default_severity": "Medium", "cwe": "CWE-521"},

    # --- Authorization (7) ---
    "idor": {"title": "Insecure Direct Object Reference (IDOR)", "group": "authorization", "default_severity": "High", "cwe": "CWE-639"},
    "bola": {"title": "Broken Object Level Authorization (BOLA)", "group": "authorization", "default_severity": "High", "cwe": "CWE-639"},
    "bfla": {"title": "Broken Function Level Authorization (BFLA)", "group": "authorization", "default_severity": "High", "cwe": "CWE-862"},
    "privilege-escalation": {"title": "Privilege Escalation", "group": "authorization", "default_severity": "Critical", "cwe": "CWE-269"},
    "tenant-isolation-failure": {"title": "Tenant Isolation Failure", "group": "authorization", "default_severity": "Critical", "cwe": "CWE-284"},
    "admin-api-exposure": {"title": "Admin API Exposure", "group": "authorization", "default_severity": "High", "cwe": "CWE-862"},
    "object-level-authz-failure": {"title": "Object-Level Authorization Failure", "group": "authorization", "default_severity": "High", "cwe": "CWE-862"},

    # --- Business Logic (9) ---
    "race-condition": {"title": "Race Condition (TOCTOU)", "group": "business-logic", "default_severity": "Medium", "cwe": "CWE-367"},
    "replay": {"title": "Replay Attack", "group": "business-logic", "default_severity": "Medium", "cwe": "CWE-294"},
    "double-spend": {"title": "Double Spend", "group": "business-logic", "default_severity": "High", "cwe": "CWE-362"},
    "coupon-abuse": {"title": "Coupon / Promo Abuse", "group": "business-logic", "default_severity": "Medium", "cwe": "CWE-840"},
    "payment-logic": {"title": "Payment Logic Flaw", "group": "business-logic", "default_severity": "Critical", "cwe": "CWE-840"},
    "state-machine-bypass": {"title": "State Machine Bypass", "group": "business-logic", "default_severity": "High", "cwe": "CWE-840"},
    "workflow-bypass": {"title": "Workflow Bypass", "group": "business-logic", "default_severity": "Medium", "cwe": "CWE-840"},
    "limit-bypass": {"title": "Rate / Limit Bypass", "group": "business-logic", "default_severity": "Low", "cwe": "CWE-799"},
    "quota-bypass": {"title": "Quota Bypass", "group": "business-logic", "default_severity": "Medium", "cwe": "CWE-799"},
    # v0.3.0 – round-3 shooting-range detectors
    "missing-rate-limiting": {"title": "Missing Rate Limiting", "group": "business-logic", "default_severity": "Medium", "cwe": "CWE-799"},
    "business-logic-flaw": {"title": "Business Logic Flaw", "group": "business-logic", "default_severity": "Medium", "cwe": "CWE-840"},

    # --- Native / Memory (14, framework placeholders) ---
    "buffer-overflow": {"title": "Buffer Overflow", "group": "native-memory", "default_severity": "Critical", "cwe": "CWE-120"},
    "heap-overflow": {"title": "Heap Overflow", "group": "native-memory", "default_severity": "Critical", "cwe": "CWE-122"},
    "stack-overflow": {"title": "Stack Overflow", "group": "native-memory", "default_severity": "Critical", "cwe": "CWE-121"},
    "use-after-free": {"title": "Use After Free", "group": "native-memory", "default_severity": "Critical", "cwe": "CWE-416"},
    "double-free": {"title": "Double Free", "group": "native-memory", "default_severity": "Critical", "cwe": "CWE-415"},
    "out-of-bounds": {"title": "Out-of-Bounds Access", "group": "native-memory", "default_severity": "Critical", "cwe": "CWE-125"},
    "integer-overflow": {"title": "Integer Overflow", "group": "native-memory", "default_severity": "High", "cwe": "CWE-190"},
    "integer-underflow": {"title": "Integer Underflow", "group": "native-memory", "default_severity": "High", "cwe": "CWE-191"},
    "signedness-bugs": {"title": "Signedness Bug", "group": "native-memory", "default_severity": "High", "cwe": "CWE-195"},
    "type-confusion": {"title": "Type Confusion", "group": "native-memory", "default_severity": "High", "cwe": "CWE-843"},
    "lifetime-bugs": {"title": "Lifetime Bug", "group": "native-memory", "default_severity": "High", "cwe": "CWE-416"},
    "iterator-invalidation": {"title": "Iterator Invalidation", "group": "native-memory", "default_severity": "Medium", "cwe": "CWE-672"},
    "null-dereference": {"title": "Null Pointer Dereference", "group": "native-memory", "default_severity": "Medium", "cwe": "CWE-476"},
    "memory-leak-security": {"title": "Security-Relevant Memory Leak", "group": "native-memory", "default_severity": "Low", "cwe": "CWE-401"},

    # --- Supply Chain / Configuration (7) ---
    "vulnerable-dependency": {"title": "Vulnerable Dependency", "group": "supply-chain", "default_severity": "High", "cwe": "CWE-1104"},
    "dependency-confusion": {"title": "Dependency Confusion", "group": "supply-chain", "default_severity": "High", "cwe": "CWE-494"},
    "unsafe-configuration": {"title": "Unsafe Configuration", "group": "supply-chain", "default_severity": "Medium", "cwe": "CWE-16"},
    "debug-interface": {"title": "Debug Interface Exposure", "group": "supply-chain", "default_severity": "High", "cwe": "CWE-489"},
    "hardcoded-secret": {"title": "Hardcoded Secret", "group": "supply-chain", "default_severity": "High", "cwe": "CWE-798"},
    "weak-cryptography": {"title": "Weak Cryptography", "group": "supply-chain", "default_severity": "Medium", "cwe": "CWE-327"},
    "insecure-defaults": {"title": "Insecure Defaults", "group": "supply-chain", "default_severity": "Medium", "cwe": "CWE-1188"},
    # v0.3.0 – round-3 shooting-range detector
    "security-misconfiguration": {"title": "Security Misconfiguration", "group": "supply-chain", "default_severity": "Medium", "cwe": "CWE-16"},
    # v0.4.0 – round-5 Django shooting-range categories
    "csrf-disabled": {"title": "CSRF Protection Disabled", "group": "security-misconfiguration", "default_severity": "Medium", "cwe": "CWE-352"},
    "ssl-verification-disabled": {"title": "SSL Verification Disabled", "group": "security-misconfiguration", "default_severity": "Medium", "cwe": "CWE-295"},
    # v0.4.3 – round-8 shooting-range misses
    "email-header-injection": {"title": "Email Header Injection", "group": "web-api", "default_severity": "Medium", "cwe": "CWE-640"},
    "insecure-temp-file": {"title": "Insecure Temporary File", "group": "web-api", "default_severity": "Low", "cwe": "CWE-377"},
}


# ===================================================================
# Known sanitizers / safe APIs (PHASE 21 counter-evidence)
# ===================================================================

SANITIZERS: Dict[str, List[str]] = {
    "sql": ["parameterized", "execute(%s", "psycopg2.sql", "SQLAlchemy ORM", "select("],
    "html": ["escape", "html.escape", "markupsafe.escape", "bleach.clean", "sanitize"],
    "url": ["urlparse", "urllib.parse", "is_safe_url", "validate_url"],
    "path": ["resolve", "abspath", "realpath", "safe_join", "secure_filename"],
    "command": ["shlex.quote", "shell=False", "argv list"],
    "xml": ["defusedxml", "XMLParser(resolve_entities=False)", "etree.fromstring"],
    "deserialization": ["yaml.safe_load", "json.loads", "pickle only trusted"],
    "file_upload": ["secure_filename", "ALLOWED_EXTENSIONS", "magic number check"],
    "auth": ["login_required", "authenticate", "verify_token", "check_password"],
    "authz": ["permission_required", "roles_required", "has_permission", "check_owner", "tenant_filter"],
}

SANITIZER_FUNCTIONS: Set[str] = set()
for _names in SANITIZERS.values():
    SANITIZER_FUNCTIONS.update(_names)


# ===================================================================
# Authentication & Authorization patterns (PHASE 6)
# ===================================================================

AUTH_PATTERNS: Dict[str, List[str]] = {
    "authentication_decorators": [
        "@login_required", "@auth_required", "@authenticate", "@requires_auth",
        "@jwt_required", "@token_auth", "@basic_auth",
    ],
    "authentication_functions": [
        "login_user", "authenticate", "verify_password", "check_password",
        "decode_token", "verify_token", "validate_session", "get_current_user",
    ],
    "authorization_decorators": [
        "@roles_required", "@permission_required", "@admin_required",
        "@requires_roles", "@has_permission", "@tenant_required",
    ],
    "authorization_functions": [
        "has_permission", "check_owner", "is_owner", "require_admin",
        "user_has_role", "check_tenant", "tenant_filter", "authorize",
    ],
    "session_management": [
        "session[", "session.get", "set_cookie", "create_session",
        "destroy_session", "rotate_session",
    ],
}


# ===================================================================
# Framework detection signatures (PHASE 0)
# ===================================================================

FRAMEWORK_SIGNATURES: Dict[str, List[str]] = {
    "flask": ["from flask", "import flask", "Flask(", "@app.route", "render_template"],
    "django": ["from django", "import django", "settings.py", "urls.py", "models.Model"],
    "fastapi": ["from fastapi", "import FastAPI", "FastAPI(", "@app.get", "Depends("],
    "tornado": ["import tornado", "tornado.web", "RequestHandler"],
    "aiohttp": ["from aiohttp", "aiohttp.web", "web.Application"],
    "pyramid": ["from pyramid", "config.add_route"],
    "bottle": ["from bottle", "bottle.route"],
    "express_js": ["express(", "require('express')", "app.get(", "router."],
    "spring": ["@RestController", "@RequestMapping", "SpringBootApplication"],
    "rails": ["class ApplicationController", "before_action", "rails"],
}


# ===================================================================
# Trust boundary types (PHASE 0)
# ===================================================================

TRUST_BOUNDARY_TYPES: List[str] = [
    "Trust Boundary",
    "Privilege Boundary",
    "Tenant Boundary",
    "Serialization Boundary",
    "Network Boundary",
    "Filesystem Boundary",
    "Database Boundary",
    "Process Boundary",
]


def category_title(category: str) -> str:
    """Return human-readable title for a category key."""
    return VULN_CATEGORIES.get(category, {}).get("title", category.replace("-", " ").title())


def default_severity(category: str) -> str:
    """Return the default severity for a category."""
    return VULN_CATEGORIES.get(category, {}).get("default_severity", "Medium")


def all_categories() -> List[str]:
    return list(VULN_CATEGORIES.keys())
