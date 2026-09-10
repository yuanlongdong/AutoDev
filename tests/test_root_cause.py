"""Tests for vulnresearch.root_cause (PHASE 9)."""
from __future__ import annotations

from vulnresearch.models import (
    AuthInfo,
    SanitizerInfo,
    SinkInfo,
    Vulnerability,
)
from vulnresearch.root_cause import (
    INSECURE_DEFAULT,
    MISSING_AUTHORIZATION,
    MISSING_INPUT_VALIDATION,
    ROOT_CAUSE_CATEGORIES,
    RootCause,
    RootCauseAnalyzer,
    TRUST_BOUNDARY_VIOLATION,
    UNSAFE_DESERIALIZATION,
    WEAK_CRYPTO,
)


def _vuln(category: str, **kw) -> Vulnerability:
    base = dict(id="V-1", title="t", category=category, severity="High",
                file="app.py", line=10, sink=SinkInfo(type=category))
    base.update(kw)
    return Vulnerability(**base)


def test_sql_injection_root_cause():
    v = _vuln(
        "sql-injection",
        sanitizer=SanitizerInfo(present="NO"),
    )
    rc = RootCauseAnalyzer().analyze(v)
    assert rc.category == MISSING_INPUT_VALIDATION
    assert "未参数化" in rc.description
    assert rc.pattern  # search pattern is non-empty


def test_command_injection_root_cause():
    rc = RootCauseAnalyzer().analyze(_vuln("command-injection"))
    assert rc.category == MISSING_INPUT_VALIDATION
    assert "shell" in rc.description


def test_idor_root_cause():
    v = _vuln(
        "idor",
        authorization=AuthInfo(required="YES", status="MISSING"),
    )
    rc = RootCauseAnalyzer().analyze(v)
    assert rc.category == MISSING_AUTHORIZATION
    assert "对象级权限检查" in rc.description


def test_hardcoded_secret_root_cause():
    rc = RootCauseAnalyzer().analyze(_vuln("hardcoded-secret"))
    assert rc.category == INSECURE_DEFAULT
    assert "硬编码" in rc.description


def test_unsafe_deserialization_root_cause():
    rc = RootCauseAnalyzer().analyze(_vuln("insecure-deserialization"))
    assert rc.category == UNSAFE_DESERIALIZATION
    assert "反序列化" in rc.description


def test_weak_crypto_root_cause():
    rc = RootCauseAnalyzer().analyze(_vuln("weak-cryptography"))
    assert rc.category == WEAK_CRYPTO


def test_path_traversal_root_cause():
    rc = RootCauseAnalyzer().analyze(_vuln("path-traversal"))
    assert rc.category == MISSING_INPUT_VALIDATION
    assert "规范化" in rc.description


def test_ssrf_root_cause():
    rc = RootCauseAnalyzer().analyze(_vuln("ssrf"))
    assert rc.category == TRUST_BOUNDARY_VIOLATION
    assert "目标地址" in rc.description


def test_batch_dedup_merges_components():
    a = _vuln("sql-injection", id="a", file="app.py", line=10)
    b = _vuln("sql-injection", id="b", file="other.py", line=20)
    c = _vuln("ssrf", id="c", file="net.py", line=5)

    results = RootCauseAnalyzer().analyze_batch([a, b, c])

    # the two SQL findings collapse into ONE root cause
    sql_rc = [r for r in results if r.category == MISSING_INPUT_VALIDATION]
    assert len(sql_rc) == 1
    assert len(sql_rc[0].affected_components) == 2
    # the SSRF finding keeps its own root cause
    assert any(r.category == TRUST_BOUNDARY_VIOLATION for r in results)


def test_all_categories_are_known_vocabulary():
    seen = {
        RootCauseAnalyzer().analyze(_vuln(c)).category
        for c in (
            "sql-injection", "command-injection", "idor", "hardcoded-secret",
            "insecure-deserialization", "weak-cryptography", "path-traversal",
            "ssrf", "xss", "ssti", "open-redirect", "auth-bypass",
            "file-upload", "race-condition",
        )
    }
    assert seen <= set(ROOT_CAUSE_CATEGORIES)


def test_root_cause_to_pattern_uses_recorded_pattern():
    rc = RootCause(
        description="x",
        category=MISSING_INPUT_VALIDATION,
        affected_components=["app.py"],
        pattern="execute\\(",
    )
    out = RootCauseAnalyzer().root_cause_to_pattern(rc)
    assert out == "execute\\("


def test_root_cause_to_pattern_falls_back_for_empty():
    rc = RootCause(description="x", category=MISSING_AUTHORIZATION,
                   affected_components=[])
    out = RootCauseAnalyzer().root_cause_to_pattern(rc)
    assert out  # default pattern exists for the class
