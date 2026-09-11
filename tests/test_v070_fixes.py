"""v0.7.0 — fourteenth hardening round.

New capabilities:
* Python 2 ``print "..."`` statement preprocessing so structured detectors run
  against Python 2 targets (the vulnerable Tornado lab).
* Tornado framework support: ``self.get_argument`` sources, ``self.render`` XSS,
  ``self.request.files`` upload, ``settings={'debug': True}`` and insecure bind.
* Bottle framework support: ``request.query/forms/params/environ.get`` sources
  and ``template(var)`` SSTI.
* Deep weak-cryptography detection: DES/3DES/RC4, ECB mode, hard-coded IV,
  disabled TLS verification.
* Seven new vulnerability-chain rules (SSRF→internal RCE, upload→webshell,
  deserial→privesc, sqli→data/auth-bypass, xss→cookie theft, open redirect→
  oauth theft, command-injection→lateral movement).
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python
from vulnresearch.detectors import (
    XSSDetector,
    SSTIDetector,
    FileUploadDetector,
    SecurityMisconfigurationDetector,
    WeakCryptoDetector,
    MissingAuthenticationDetector,
    is_route_handler,
)
from vulnresearch.chain_analyzer import ChainAnalyzer
from vulnresearch.callgraph import CallGraph
from vulnresearch.models import SinkInfo, Vulnerability

FIXTURES = Path(__file__).parent / "fixtures" / "v070"


def _run(detector, fixture: str):
    path = FIXTURES / fixture
    ir = extract_python(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    out = []
    for fn in ir.functions:
        out.extend(detector.detect(fn, lines, ir))
    return out, ir


def _vuln(id_: str, category: str, severity: str = "High") -> Vulnerability:
    return Vulnerability(
        id=id_, title=category, category=category, severity=severity,
        file="app.py", line=1, sink=SinkInfo(type=category),
    )


def _empty_graph() -> CallGraph:
    return CallGraph(nodes={}, edges={})


# ---------------------------------------------------------------------------
# 1. Python 2 compatibility
# ---------------------------------------------------------------------------

def test_python2_print_statement_parsed_structurally():
    """A file with ``print "GET "`` must yield functions, not an empty IR."""
    out, ir = _run(XSSDetector(), "tornado_features.py")
    assert len(ir.functions) > 0, "Python 2 print statement broke IR extraction"
    names = {f.name for f in ir.functions}
    assert "get" in names and "post" in names


def test_python2_print_does_not_touch_disk():
    """Preprocessing is in-memory: the on-disk file keeps the print statement."""
    path = FIXTURES / "tornado_features.py"
    assert 'print "GET "' in path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 2. Tornado support
# ---------------------------------------------------------------------------

def test_tornado_handler_methods_are_route_handlers():
    _, ir = _run(XSSDetector(), "tornado_features.py")
    handlers = {f.qualified_name for f in ir.functions if is_route_handler(f)}
    assert "SearchHandler.get" in handlers, handlers
    assert "UploadHandler.post" in handlers, handlers
    # module-level helper must NOT be treated as a route handler
    assert "make_app" not in handlers, handlers


def test_tornado_self_render_xss():
    out, _ = _run(XSSDetector(), "tornado_features.py")
    lines = {v.line for v in out if v.category == "xss"}
    assert any(l == 11 for l in lines), out  # self.render(..., query=query)


def test_tornado_request_files_upload():
    out, _ = _run(FileUploadDetector(), "tornado_features.py")
    assert any(v.category == "file-upload" for v in out), out


def test_tornado_debug_settings_and_insecure_bind():
    out, _ = _run(SecurityMisconfigurationDetector(), "tornado_features.py")
    text = " ".join(v.evidence.proof + v.snippet for v in out)
    assert "debug" in text.lower(), out
    assert "0.0.0.0" in text, out


# ---------------------------------------------------------------------------
# 3. Bottle support
# ---------------------------------------------------------------------------

def test_bottle_template_var_ssti():
    out, _ = _run(SSTIDetector(), "bottle_features.py")
    ssti_fns = {v.function for v in out if v.category == "ssti"}
    assert "help_view" in ssti_fns, out


def test_bottle_static_template_name_not_ssti():
    out, _ = _run(SSTIDetector(), "bottle_features.py")
    ssti_fns = {v.function for v in out if v.category == "ssti"}
    # template('login.html', ...) / template('profile.html', ...) are static names
    assert "login_view" not in ssti_fns, out
    assert "profile_view" not in ssti_fns, out


def test_bottle_request_sources_recognised():
    _, ir = _run(SSTIDetector(), "bottle_features.py")
    # request.query.get / request.forms.get / request.params.get are sources
    src_owner = {f.name: f.sources for f in ir.functions}
    assert any("request.query.get" in s for s in src_owner.values()), src_owner


# ---------------------------------------------------------------------------
# 4. Deep weak cryptography
# ---------------------------------------------------------------------------

def test_crypto_des_ecb_hardcoded_iv_tls():
    out, _ = _run(WeakCryptoDetector(), "crypto_features.py")
    text = " ".join(v.snippet for v in out).lower()
    assert any("des.new" in s or "des." in s for s in text.splitlines()) or "des" in text
    assert "mode_ecb" in text, out
    assert "iv=b'1234567890123456'" in text, out
    assert "unverified_context" in text, out
    assert "cert_none" in text, out


# ---------------------------------------------------------------------------
# 5. New vulnerability chains
# ---------------------------------------------------------------------------

def test_ssrf_to_internal_rce_chain():
    chains = ChainAnalyzer().find_chains(
        [_vuln("s", "ssrf"), _vuln("c", "command-injection")], _empty_graph())
    assert any("ssrf-to-internal-rce" in c.chain_id and c.combined_severity == "Critical"
               for c in chains)


def test_deserial_to_privesc_chain():
    chains = ChainAnalyzer().find_chains(
        [_vuln("d", "insecure-deserialization"),
         _vuln("c", "code-injection"),
         _vuln("p", "privilege-escalation")], _empty_graph())
    assert any("deserial-to-privesc" in c.chain_id for c in chains)


def test_xss_cookie_theft_chain():
    chains = ChainAnalyzer().find_chains(
        [_vuln("x", "xss"), _vuln("ck", "insecure-cookie")], _empty_graph())
    assert any("xss-cookie-theft" in c.chain_id and c.combined_severity == "High"
               for c in chains)


def test_open_redirect_oauth_theft_chain():
    chains = ChainAnalyzer().find_chains(
        [_vuln("r", "open-redirect"), _vuln("j", "jwt-flaws")], _empty_graph())
    assert any("redirect-oauth-theft" in c.chain_id for c in chains)


def test_cmd_injection_lateral_movement_chain():
    chains = ChainAnalyzer().find_chains(
        [_vuln("c", "command-injection"),
         _vuln("s", "ssrf"),
         _vuln("d", "sensitive-data-exposure")], _empty_graph())
    assert any("cmdi-lateral-move" in c.chain_id for c in chains)


def test_sqli_data_authbypass_chain():
    chains = ChainAnalyzer().find_chains(
        [_vuln("s", "sql-injection"),
         _vuln("d", "sensitive-data-exposure"),
         _vuln("a", "auth-bypass")], _empty_graph())
    assert any("sqli-data-authbypass" in c.chain_id for c in chains)


def test_upload_webshell_chain():
    chains = ChainAnalyzer().find_chains(
        [_vuln("u", "file-upload"),
         _vuln("p", "path-traversal"),
         _vuln("w", "arbitrary-file-write")], _empty_graph())
    assert any("upload-webshell" in c.chain_id and c.combined_severity == "Critical"
               for c in chains)
