"""Tests for vulnresearch.chain_analyzer (PHASE 10)."""
from __future__ import annotations

from vulnresearch.callgraph import CallGraph
from vulnresearch.chain_analyzer import ChainAnalyzer, VulnerabilityChain
from vulnresearch.models import SinkInfo, Vulnerability


def _vuln(id_: str, category: str, severity: str = "High") -> Vulnerability:
    return Vulnerability(
        id=id_,
        title=category,
        category=category,
        severity=severity,
        file="app.py",
        line=1,
        sink=SinkInfo(type=category),
    )


def _empty_graph() -> CallGraph:
    return CallGraph(nodes={}, edges={})


def test_auth_bypass_plus_file_read_chain():
    bypass = _vuln("b1", "auth-bypass")
    fileread = _vuln("f1", "arbitrary-file-read")
    chains = ChainAnalyzer().find_chains([bypass, fileread], _empty_graph())

    assert chains, "expected a sensitive-data-exposure chain"
    chain = next(c for c in chains if "sensitive-data" in c.chain_id)
    assert chain.combined_severity == "Critical"
    assert {v.category for v in chain.steps} == {"auth-bypass", "arbitrary-file-read"}
    assert "数据泄露" in chain.description


def test_ssrf_plus_internal_api_chain():
    ssrf = _vuln("s1", "ssrf")
    internal = _vuln("i1", "admin-api-exposure")
    chains = ChainAnalyzer().find_chains([ssrf, internal], _empty_graph())

    chain = next(c for c in chains if "internal-network" in c.chain_id)
    assert chain.combined_severity == "High"
    assert "内网" in chain.description


def test_no_chain_when_unrelated():
    lone = _vuln("l1", "xss")
    chains = ChainAnalyzer().find_chains([lone], _empty_graph())
    assert chains == []


def test_no_chain_when_mismatched_pair():
    ssrf = _vuln("s1", "ssrf")
    xss = _vuln("x1", "xss")  # open-redirect is the XSS partner, not ssrf
    assert ChainAnalyzer().find_chains([ssrf, xss], _empty_graph()) == []


def test_upload_path_traversal_rce_chain():
    upload = _vuln("u1", "file-upload", severity="High")
    traversal = _vuln("t1", "path-traversal", severity="High")
    chains = ChainAnalyzer().find_chains([upload, traversal], _empty_graph())
    assert any("upload-to-rce" in c.chain_id and c.combined_severity == "Critical"
               for c in chains)


def test_phishing_chain():
    redirect = _vuln("r1", "open-redirect", severity="Low")
    xss = _vuln("x1", "xss", severity="Medium")
    chains = ChainAnalyzer().find_chains([redirect, xss], _empty_graph())
    assert any("phishing" in c.chain_id and c.combined_severity == "Medium"
               for c in chains)


def test_combined_severity_takes_worst_member():
    chain = VulnerabilityChain(
        chain_id="CHAIN-x",
        steps=[_vuln("a", "open-redirect", "Low"),
               _vuln("b", "xss", "Critical")],
        combined_severity="Medium",
        description="x",
    )
    # the Critical member escalates the Medium band
    assert ChainAnalyzer.combined_severity(chain) == "Critical"


def test_distinct_vulns_required_per_step():
    """One finding cannot serve two slots of the same chain."""
    # only ONE finding present, even though it would alone not match a rule.
    lone = _vuln("only", "auth-bypass")
    assert ChainAnalyzer().find_chains([lone], _empty_graph()) == []
