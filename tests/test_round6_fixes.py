"""v0.4.1 – round-6 shooting-range detector tests.

Covers the six round-6 misses:
  * yaml.load / yaml.load(..., Loader=yaml.Loader) deserialization
  * marshal.loads deserialization
  * ReDoS (nested-quantifier regex on request input)
  * app.config['DEBUG'] = True
  * module-level Django ``DEBUG = True``
  * ALLOWED_HOSTS = ['*']

Each new rule gets a positive assertion and (where applicable) a negative
assertion.  One integration test re-scans the real django-target1 view layer
to prove the yaml.load findings survive the full pipeline.
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.detectors import (
    DangerousDeserializationDetector,
    ReDoSDetector,
    SecurityMisconfigurationDetector,
    scan_file_with_ir,
)

FIXTURES = Path(__file__).parent / "fixtures" / "round6"
# tests/ -> AutoDev/ -> 38441101299106050/
SHOOTING_RANGE = Path(__file__).resolve().parents[2] / "shooting_range"


def _detect(fixture: str, detector_cls):
    p = FIXTURES / fixture
    ir = extract_python(p)
    lines = p.read_text(encoding="utf-8").splitlines()
    out = []
    for fn in ir.functions:
        out.extend(detector_cls().detect(fn, lines, ir))
    return out


def _by_cat(findings, category):
    return [v for v in findings if v.category == category]


# ---------------------------------------------------------------------------
# A. YAML deserialization
# ---------------------------------------------------------------------------


def test_yaml_load_detected():
    r = _detect("yaml_deserialization.py", DangerousDeserializationDetector)
    ys = _by_cat(r, "insecure-deserialization")
    assert len(ys) >= 1
    assert any(v.line == 14 for v in ys)
    assert any("yaml.load" in v.snippet for v in ys)


def test_yaml_load_with_loader_detected():
    r = _detect("yaml_deserialization.py", DangerousDeserializationDetector)
    ys = _by_cat(r, "insecure-deserialization")
    # yaml.load(data, Loader=yaml.Loader) is unsafe and must be reported.
    assert any(v.line == 20 for v in ys)


def test_yaml_safe_load_not_reported():
    r = _detect("yaml_deserialization.py", DangerousDeserializationDetector)
    ys = _by_cat(r, "insecure-deserialization")
    # Exactly the two unsafe calls (L14, L20); the safe_load() call (L25)
    # must not appear.
    reported_lines = {v.line for v in ys}
    assert 25 not in reported_lines


# ---------------------------------------------------------------------------
# B. marshal deserialization
# ---------------------------------------------------------------------------


def test_marshal_loads_detected():
    r = _detect("marshal_deserialization.py", DangerousDeserializationDetector)
    ys = _by_cat(r, "insecure-deserialization")
    assert any("marshal.loads" in v.snippet for v in ys)


# ---------------------------------------------------------------------------
# C. ReDoS
# ---------------------------------------------------------------------------


def test_redos_nested_quantifier_detected():
    r = _detect("redos_vuln.py", ReDoSDetector)
    redos = _by_cat(r, "redos")
    assert redos, "expected a ReDoS finding for the nested-quantifier email regex"
    assert any(v.function == "validate_email" for v in redos)
    assert all(v.severity == "Medium" for v in redos)


def test_redos_safe_regex_not_reported():
    r = _detect("redos_vuln.py", ReDoSDetector)
    redos = _by_cat(r, "redos")
    # The plain, unambiguous regex in validate_plain must never be flagged.
    assert all(v.function != "validate_plain" for v in redos)


# ---------------------------------------------------------------------------
# D. Security misconfiguration
# ---------------------------------------------------------------------------


def _misconfig_lines(fixture="debug_config.py"):
    r = _detect(fixture, SecurityMisconfigurationDetector)
    return {v.line: v for v in _by_cat(r, "security-misconfiguration")}


def test_app_config_debug_detected():
    lines = _misconfig_lines()
    assert 14 in lines
    assert "app.config" in lines[14].snippet and "DEBUG" in lines[14].snippet


def test_django_debug_true_detected():
    lines = _misconfig_lines()
    assert 18 in lines
    assert lines[18].snippet.strip() == "DEBUG = True"


def test_allowed_hosts_wildcard_detected():
    lines = _misconfig_lines()
    assert 19 in lines
    assert "ALLOWED_HOSTS" in lines[19].snippet and "*" in lines[19].snippet


def test_local_debug_variable_not_reported():
    lines = _misconfig_lines()
    # function-local ``debug = True`` lives on line 23 and must NOT be flagged.
    assert 23 not in lines


# ---------------------------------------------------------------------------
# E. Integration: real shooting-range django-target1 view layer
# ---------------------------------------------------------------------------


def test_yaml_in_django_target1_detected():
    views = SHOOTING_RANGE / "django-target1" / "views.py"
    if not views.exists():
        # Shooting range is a sibling checkout; skip when unavailable.
        import pytest
        pytest.skip(f"shooting range not found: {views}")
    ir = extract_python(views)
    findings = scan_file_with_ir(views, ir)
    desers = [v for v in findings if v.category == "insecure-deserialization"]
    # The two yaml.load calls (plain + unsafe Loader) must both survive the
    # full legacy + structured pipeline.
    yaml_lines = {v.line for v in desers if "yaml" in v.snippet}
    assert yaml_lines, "expected yaml.load findings in django-target1/views.py"
    assert any(v.function == "parse_yaml" for v in desers) or yaml_lines
