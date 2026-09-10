"""Non-destructive security verification framework (PHASE 13).

Verification is **static-proof first**.  The framework never executes the
analysed code, never sends exploit payloads and never performs network I/O.
It walks a fixed priority ladder:

1. **static**       – taint analysis already proved source → sink reachability
2. **unit**         – a regression unit test exists for the finding
3. **integration**  – integration test configuration is present
4. **docker**      – sandbox reproduction (framework placeholder)
5. **authorized**  – dedicated authorised test environment (placeholder)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import Vulnerability


# Canonical verification priority ladder (PHASE 13).
VERIFICATION_PRIORITY: List[str] = ["static", "unit", "integration", "docker", "authorized"]


@dataclass
class VerificationResult:
    """Outcome of a single verification attempt (always non-destructive)."""

    environment: str
    method: str
    result: str           # confirmed / test_exists / no_test / not_implemented / pending
    details: str = ""
    non_destructive: bool = True


class Verifier:
    """Prove vulnerabilities statically and suggest safe reproduction paths."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verification_priority(self) -> List[str]:
        """Return the ordered verification priority ladder."""
        return list(VERIFICATION_PRIORITY)

    def verify(self, vuln: Vulnerability, project_ir: Any = None) -> VerificationResult:
        """Run the verification ladder for *vuln* and return the first result.

        The ladder is evaluated in priority order; the first stage that yields a
        conclusive answer wins.  Every stage is non-destructive.
        """
        # 1. Static proof – the highest-value, zero-risk confirmation.
        if self.static_proof(vuln, project_ir):
            vuln.verification.environment = "static"
            vuln.verification.method = "taint_analysis"
            vuln.verification.result = "confirmed"
            return VerificationResult(
                environment="static",
                method="taint_analysis",
                result="confirmed",
                details=(
                    f"Source '{vuln.source.type}' reaches sink "
                    f"'{vuln.sink.type}' via {len(vuln.data_flow)} proven hop(s); "
                    "reachability = REACHABLE."
                ),
                non_destructive=True,
            )

        # 2. Local unit test presence.
        unit = self._check_unit_test(vuln)
        if unit is not None:
            return unit

        # 3. Local integration test configuration.
        integration = self._check_integration_test(vuln)
        if integration is not None:
            return integration

        # 4. Docker / sandbox reproduction – framework placeholder.
        return VerificationResult(
            environment="docker",
            method="sandbox_reproduction",
            result="not_implemented",
            details="Docker/sandbox reproduction is a framework placeholder; "
                    "no sandbox is provisioned.",
            non_destructive=True,
        )

    # ------------------------------------------------------------------
    # Stage 1 – static proof
    # ------------------------------------------------------------------

    def static_proof(self, vuln: Vulnerability, project_ir: Any = None) -> bool:
        """Return ``True`` when static taint analysis confirms the chain.

        A static proof requires:

        * a non-empty, ordered :attr:`Vulnerability.data_flow`, and
        * :attr:`Vulnerability.reachability.status` == ``"REACHABLE"``, and
        * both a source type and a sink type are known.

        When *project_ir* is supplied it is used as supporting context but the
        proof itself never mutates or executes it.
        """
        if vuln.source.type in ("", "UNKNOWN"):
            return False
        if not vuln.sink.type:
            return False
        if not vuln.data_flow:
            return False
        if vuln.reachability.status != "REACHABLE":
            return False
        # The individual steps must each carry a location or transformation so
        # the chain is genuinely traceable rather than a placeholder hop.
        traceable = sum(
            1 for step in vuln.data_flow
            if step.location or step.transformation or step.step
        )
        return traceable >= len(vuln.data_flow)

    # ------------------------------------------------------------------
    # Stage 2 – unit test
    # ------------------------------------------------------------------

    def _check_unit_test(self, vuln: Vulnerability) -> Optional[VerificationResult]:
        """Look for a test file referencing the vulnerable location/category."""
        path = Path(vuln.file) if vuln.file else None
        test_exists = False
        details = ""

        candidates: List[Path] = []
        if path is not None:
            # Conventional pytest / unittest locations relative to the project.
            project_root = self._project_root(path)
            candidates.extend(self._candidate_test_paths(project_root, vuln))

        for cand in candidates:
            if cand.is_file():
                try:
                    text = cand.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                tokens = [vuln.category, Path(vuln.file).stem]
                if any(tok and tok in text for tok in tokens):
                    test_exists = True
                    details = f"Matching unit test found: {cand}"
                    break

        result = "test_exists" if test_exists else "no_test"
        if not test_exists:
            details = "No unit test currently covers this vulnerability; see find_regression_test()."
        return VerificationResult(
            environment="unit",
            method="unit_test_lookup",
            result=result,
            details=details,
            non_destructive=True,
        )

    # ------------------------------------------------------------------
    # Stage 3 – integration test
    # ------------------------------------------------------------------

    def _check_integration_test(self, vuln: Vulnerability) -> Optional[VerificationResult]:
        path = Path(vuln.file) if vuln.file else None
        if path is None:
            return None
        project_root = self._project_root(path)
        for name in ("pytest.ini", "tox.ini", "conftest.py", "docker-compose.yml",
                     "docker-compose.yaml", ".github/workflows"):
            if (project_root / name).exists():
                return VerificationResult(
                    environment="integration",
                    method="integration_config_lookup",
                    result="test_exists",
                    details=f"Integration test configuration detected: {name}",
                    non_destructive=True,
                )
        return VerificationResult(
            environment="integration",
            method="integration_config_lookup",
            result="no_test",
            details="No integration-test configuration detected.",
            non_destructive=True,
        )

    # ------------------------------------------------------------------
    # Regression test suggestion
    # ------------------------------------------------------------------

    def find_regression_test(self, vuln: Vulnerability) -> str:
        """Return suggested regression-test name and content (as a Markdown string)."""
        name = self._test_name(vuln)
        body = self._test_body(vuln)
        return (
            f"### Suggested regression test: `{name}`\n\n"
            "```python\n"
            f"{body}"
            "```\n\n"
            f"*Targets `{vuln.category}` at `{vuln.file}:{vuln.line}`.*"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _project_root(path: Path) -> Path:
        """Walk up until a project marker (tests/ or pyproject) is found."""
        cur = path.parent
        for _ in range(6):
            if (cur / "tests").is_dir() or (cur / "pyproject.toml").exists():
                return cur
            if cur.parent == cur:
                break
            cur = cur.parent
        return path.parent

    @staticmethod
    def _candidate_test_paths(project_root: Path, vuln: Vulnerability) -> List[Path]:
        stem = Path(vuln.file).stem
        return [
            project_root / "tests" / f"test_{stem}.py",
            project_root / "tests" / f"test_{vuln.category}.py",
            project_root / "test" / f"test_{stem}.py",
        ]

    @staticmethod
    def _test_name(vuln: Vulnerability) -> str:
        base = (vuln.category or "vulnerability").replace("-", "_")
        return f"test_regression_{base}_{vuln.line}"

    @staticmethod
    def _test_body(vuln: Vulnerability) -> str:
        return (
            f"def {Verifier._test_name(vuln)}():\n"
            f"    # Regression guard for {vuln.id} ({vuln.title})\n"
            f"    payload = {{attacker_controlled_input}}\n"
            f"    out = vulnerable_handler(payload)\n"
            f"    assert not is_dangerous(out), "
            f"'{vuln.category} regression'\n"
        )
