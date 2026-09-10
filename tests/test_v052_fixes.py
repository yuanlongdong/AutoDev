"""v0.5.2 — fixes for the three new shooting ranges.

* SSRF via aliased imports: ``import requests as req; req.get(url)`` was missed
  because the sink set only matched the fully-qualified ``requests.get`` name
  (Pentrix webhook blind-SSRF).
* Open-redirect false positives: ``redirect(url_for("static_endpoint"))`` was
  treated as a user-controlled redirect even though ``url_for`` builds an
  internal route from a string literal (chain-target, pickle-cookie-target).
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.ir import extract_python, extract_file
from vulnresearch.detectors import (
    SSRFDetector,
    OpenRedirectDetector,
    _import_alias_map,
    scan_file_with_ir,
)

FIXTURES = Path(__file__).parent / "fixtures" / "v052"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_function_level(source: str, detector):
    """Run *detector* over every function in *source*; return Vulnerabilities."""
    p = Path("/tmp/_v052_unit.py")
    p.write_text(source, encoding="utf-8")
    ir = extract_python(p)
    lines = source.splitlines()
    out = []
    for fn in ir.functions:
        out.extend(detector.detect(fn, lines, ir))
    return out


# ---------------------------------------------------------------------------
# 1. SSRF — aliased import
# ---------------------------------------------------------------------------

def test_import_alias_map_parses_requests_as():
    m = _import_alias_map(["import requests as req", "import httpx"])
    assert m["req"] == "requests"
    assert m["httpx"] == "httpx"


def test_import_alias_map_parses_from_import():
    m = _import_alias_map(["from requests import get as g", "from requests import post"])
    assert m["g"] == "requests.get"
    assert m["post"] == "requests.post"


def test_aliased_req_get_url_reported():
    src = (
        "@app.route('/w', methods=['POST'])\n"
        "def w():\n"
        "    url = request.form.get('url')\n"
        "    import requests as req\n"
        "    req.get(url, timeout=5)\n"
        "    return 'ok'\n"
    )
    out = _detect_function_level(src, SSRFDetector())
    assert any(v.category == "ssrf" for v in out), out


def test_aliased_req_post_callback_reported():
    src = (
        "@app.route('/cb', methods=['POST'])\n"
        "def cb():\n"
        "    callback_url = request.form.get('url')\n"
        "    import requests as req\n"
        "    req.post(callback_url, json={'status': 'ok'}, timeout=3)\n"
        "    return 'ok'\n"
    )
    out = _detect_function_level(src, SSRFDetector())
    assert any(v.category == "ssrf" for v in out), out


def test_aliased_req_post_data_not_reported():
    """``req.post(data)`` where ``data`` has no network semantics is safe."""
    src = (
        "@app.route('/n', methods=['POST'])\n"
        "def n():\n"
        "    data = request.form.get('payload')\n"
        "    import requests as req\n"
        "    req.post(data, timeout=3)\n"
        "    return 'ok'\n"
    )
    out = _detect_function_level(src, SSRFDetector())
    assert not any(v.category == "ssrf" for v in out), out


def test_aliased_ssrf_fixture():
    p = FIXTURES / "ssrf_alias.py"
    findings = scan_file_with_ir(p, extract_file(p))
    ssrf = [v for v in findings if v.category == "ssrf"]
    # webhook (req.post callback_url), fetch (req.get url), from_alias (g url).
    # notify() posts ``data`` with no network token -> NOT reported.
    assert len(ssrf) == 3, [(v.line, v.snippet) for v in ssrf]


# ---------------------------------------------------------------------------
# 2. Open redirect — url_for literal guard
# ---------------------------------------------------------------------------

def test_url_for_literal_not_reported():
    """Reproduces the chain-target / pickle-cookie false positive: a handler
    that touches ``request.*`` but redirects to a static internal route."""
    src = (
        "@app.route('/login')\n"
        "def login():\n"
        "    next_url = request.args.get('next')\n"
        "    return redirect(url_for('auth.login'))\n"
    )
    out = _detect_function_level(src, OpenRedirectDetector())
    assert not any(v.category == "open-redirect" for v in out), out


def test_redirect_variable_reported():
    src = (
        "@app.route('/go')\n"
        "def go():\n"
        "    target = request.args.get('next')\n"
        "    return redirect(target)\n"
    )
    out = _detect_function_level(src, OpenRedirectDetector())
    assert any(v.category == "open-redirect" for v in out), out


def test_redirect_literal_path_not_reported():
    src = (
        "@app.route('/s')\n"
        "def s():\n"
        "    return redirect('/login')\n"
    )
    out = _detect_function_level(src, OpenRedirectDetector())
    assert not any(v.category == "open-redirect" for v in out), out


def test_fastapi_redirect_response_url_kept():
    """FastAPI ``RedirectResponse(url=next)`` with a tainted route param must
    STILL be reported (regression guard)."""
    src = (
        "@router.get('/go')\n"
        "def go(next: str):\n"
        "    return RedirectResponse(url=next)\n"
    )
    out = _detect_function_level(src, OpenRedirectDetector())
    assert any(v.category == "open-redirect" for v in out), out


def test_url_for_dynamic_endpoint_reported():
    """``redirect(url_for(endpoint_var))`` with a tainted variable still fires."""
    src = (
        "@app.route('/dyn')\n"
        "def dyn():\n"
        "    endpoint = request.args.get('ep')\n"
        "    return redirect(url_for(endpoint))\n"
    )
    out = _detect_function_level(src, OpenRedirectDetector())
    assert any(v.category == "open-redirect" for v in out), out


def test_open_redirect_fixture():
    p = FIXTURES / "open_redirect.py"
    findings = scan_file_with_ir(p, extract_file(p))
    orf = [v for v in findings if v.category == "open-redirect"]
    # user_next (redirect target) + dyn_endpoint (url_for(var)) only.
    assert len(orf) == 2, [(v.line, v.snippet) for v in orf]
