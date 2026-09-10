from pathlib import Path
from typing import Iterable, List
from .detectors import scan_file
from .models import Finding
from .taint import analyze_python_taint

DEFAULT_EXCLUDES = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
DEFAULT_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".php", ".rb", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp", ".cs"}


class ResearchEngine:
    def __init__(self, root: str, max_files: int = 10000):
        self.root = Path(root).resolve()
        self.max_files = max_files

    def files(self) -> Iterable[Path]:
        count = 0
        for p in self.root.rglob("*"):
            if count >= self.max_files:
                break
            if not p.is_file() or p.suffix.lower() not in DEFAULT_EXTS:
                continue
            if any(part in DEFAULT_EXCLUDES for part in p.parts):
                continue
            count += 1
            yield p

    @staticmethod
    def _taint_findings(path: Path) -> List[Finding]:
        findings = []
        for flow in analyze_python_taint(path):
            # E2 proves a local source-to-sink data-flow candidate, but not exploitability.
            findings.append(Finding(
                title=f"Potential {flow.sink} injection/data-flow issue",
                category="taint-flow",
                severity="High",
                confidence="Medium",
                evidence=(
                    f"E2: local source-to-sink flow detected: {flow.source} -> "
                    f"{flow.expression} -> {flow.sink}; sanitizer={flow.sanitizer}"
                ),
                path=str(path),
                line=flow.line,
                snippet=flow.expression,
                source=flow.source,
                sink=flow.sink,
                root_cause="Untrusted input reaches a security-sensitive sink within one function.",
                remediation="Validate/allowlist untrusted input and use the sink's safe parameterized API where applicable.",
                status="likely",
                evidence_level="E2",
                sanitizer=flow.sanitizer,
                reachability="LOCAL",
            ))
        return findings

    def run(self) -> List[Finding]:
        findings = []
        for path in self.files():
            findings.extend(scan_file(path))
            if path.suffix.lower() == ".py":
                findings.extend(self._taint_findings(path))
        return self.deduplicate(findings)

    @staticmethod
    def deduplicate(findings: List[Finding]) -> List[Finding]:
        seen = set()
        result = []
        for f in findings:
            key = (f.category, f.path, f.line, f.snippet)
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result
