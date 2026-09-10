"""Safe AST analysis facade.

The engine only parses source files and builds a project IR. It never imports,
executes, or sends data to the analyzed project.
"""
from pathlib import Path
from typing import Iterable
from .ir import ProjectIR, extract_file


class ASTResearchEngine:
    def __init__(self, root: str, max_files: int = 10000):
        self.root = Path(root).resolve()
        self.max_files = max_files

    def files(self) -> Iterable[Path]:
        # v0.3.1: ``root`` may point at a single .py file — ``rglob`` never
        # yields the file itself, so handle that case directly.
        if self.root.is_file():
            if self.root.suffix.lower() == ".py":
                yield self.root
            return
        count = 0
        excludes = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
        for path in self.root.rglob("*"):
            if count >= self.max_files:
                return
            if not path.is_file() or any(part in excludes for part in path.parts):
                continue
            if path.suffix.lower() != ".py":
                continue
            count += 1
            yield path

    def run(self) -> ProjectIR:
        functions = []
        for path in self.files():
            functions.extend(extract_file(path).functions)
        return ProjectIR(functions)
