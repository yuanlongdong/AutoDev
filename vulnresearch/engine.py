from pathlib import Path
from collections import defaultdict
from typing import Iterable, List
from .detectors import scan_file
from .models import Finding

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

    def run(self) -> List[Finding]:
        findings = []
        for path in self.files():
            findings.extend(scan_file(path))
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
