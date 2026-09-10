"""Shared pytest fixtures / helpers for the vulnresearch test-suite."""
from __future__ import annotations

from typing import List, Optional

import pytest

from vulnresearch.models import (
    DataFlowStep,
    EvidenceInfo,
    ImpactInfo,
    ReachabilityInfo,
    SanitizerInfo,
    SinkInfo,
    SourceInfo,
    Vulnerability,
)


def make_vuln(
    id: str = "VULN-00001",
    category: str = "sql-injection",
    severity: str = "High",
    status: str = "potential",
    confidence: str = "Low",
    file: str = "app.py",
    line: int = 10,
    function: str = "view",
    snippet: str = "db.execute(query)",
    source_type: str = "UNKNOWN",
    data_flow: Optional[List[DataFlowStep]] = None,
    reachability: str = "UNKNOWN",
    root_cause: str = "",
    evidence_level: str = "E1",
    remediation: str = "Use parameterised queries.",
) -> Vulnerability:
    """Build a populated :class:`Vulnerability` for tests."""
    return Vulnerability(
        id=id,
        title="SQL Injection",
        category=category,
        severity=severity,
        status=status,
        confidence=confidence,
        file=file,
        line=line,
        function=function,
        snippet=snippet,
        source=SourceInfo(type=source_type),
        data_flow=list(data_flow or []),
        sanitizer=SanitizerInfo(present="UNKNOWN"),
        reachability=ReachabilityInfo(status=reachability),
        sink=SinkInfo(type="sql", location=f"{file}:{line}"),
        impact=ImpactInfo(),
        evidence=EvidenceInfo(level=evidence_level, proof="suspicious sink"),
        root_cause=root_cause,
        remediation=remediation,
    )


@pytest.fixture
def vuln_factory():
    return make_vuln
