"""Conservative source/sink detectors. They report evidence, never execute payloads."""
from pathlib import Path
import re
from .models import Finding

RULES = [
    ("SQL Injection", "sql-injection", "High", re.compile(r"(?:execute|executemany|raw|query)\s*\([^\n]*(?:f['\"]|['\"][^'\"]*\+|\.format\()", re.I), "Use parameterized queries."),
    ("Command Injection", "command-injection", "Critical", re.compile(r"(?:os\.system|subprocess\.(?:run|Popen|call)|os\.popen)\s*\([^\n]*(?:f['\"]|['\"][^'\"]*\+|\.format\()", re.I), "Pass argv as a list and avoid shell interpretation."),
    ("Path Traversal", "path-traversal", "High", re.compile(r"(?:open|Path\s*\(|read_text|read_bytes)\s*\([^\n]*(?:request|params|query|filename|filepath|path)", re.I), "Constrain paths to an allowlisted directory and resolve before access."),
    ("SSRF", "ssrf", "High", re.compile(r"(?:requests\.(?:get|post|put|delete|request)|urllib\.request\.(?:urlopen|Request))\s*\([^\n]*(?:url|uri|target|callback|redirect)", re.I), "Allowlist schemes/hosts and block private/link-local destinations."),
    ("Hardcoded Secret", "secret", "High", re.compile(r"(?i)(?:api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}['\"]"), "Move secrets to a secret manager or environment configuration."),
    ("Dangerous Deserialization", "deserialization", "Critical", re.compile(r"(?:pickle\.(?:load|loads)|yaml\.load\s*\([^\n]*Loader\s*=\s*(?!yaml\.SafeLoader))", re.I), "Use safe, data-only deserialization."),
    ("Potential XSS", "xss", "Medium", re.compile(r"(?:render_template_string|Markup\s*\(|mark_safe\s*\()", re.I), "Prefer contextual output encoding and safe template APIs."),
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
