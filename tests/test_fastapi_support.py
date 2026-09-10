"""v0.5.0 – FastAPI / Starlette framework support.

Each test mirrors a false negative discovered on the FastAPI shooting ranges:

* open redirect via ``RedirectResponse(url=next)``;
* CORS via module-level ``CORSMiddleware`` + wildcard + credentials;
* auth bypass on ``/api/admin/...`` with no ``Depends``;
* IDOR on a ``{path_param}`` route with authentication but no ownership check;
* path traversal via a FastAPI query parameter reaching ``FileResponse``;
* hardcoded fallback secret in ``os.environ.get("K", "default")``;
* NoSQL injection via ``await request.json()`` forwarded to a mongo helper.

The companion ``safe.py`` fixture must not produce any of these categories.
"""
from __future__ import annotations

from pathlib import Path

from vulnresearch.engine import ResearchEngine

FIXTURES = Path(__file__).parent / "fixtures" / "fastapi"


def _categories(path: Path) -> dict:
    eng = ResearchEngine(str(path), max_files=10000)
    findings = eng.run()
    out: dict = {}
    for f in findings:
        out.setdefault(f.category, []).append(f.line)
    return out


def test_vulnerable_fixture_covers_all_fastapi_categories():
    cats = _categories(FIXTURES / "vulnerable.py")
    for expected in (
        "open-redirect",
        "cors-misconfiguration",
        "auth-bypass",
        "idor",
        "path-traversal",
        "hardcoded-secret",
        "nosql-injection",
    ):
        assert expected in cats, f"missing {expected}; got {sorted(cats)}"


def test_open_redirect_redirect_response():
    cats = _categories(FIXTURES / "vulnerable.py")
    assert cats["open-redirect"]


def test_cors_middleware_wildcard_credentials():
    cats = _categories(FIXTURES / "vulnerable.py")
    assert "cors-misconfiguration" in cats


def test_admin_route_without_depends_reported():
    cats = _categories(FIXTURES / "vulnerable.py")
    assert "auth-bypass" in cats


def test_idor_path_param_without_ownership_check():
    cats = _categories(FIXTURES / "vulnerable.py")
    assert "idor" in cats


def test_path_traversal_query_param_to_fileresponse():
    cats = _categories(FIXTURES / "vulnerable.py")
    assert "path-traversal" in cats


def test_hardcoded_secret_os_environ_default():
    cats = _categories(FIXTURES / "vulnerable.py")
    assert "hardcoded-secret" in cats


def test_nosql_request_json_and_query_param():
    cats = _categories(FIXTURES / "vulnerable.py")
    # both the POST request.json() path and the GET route-param path
    assert len(cats["nosql-injection"]) >= 2


def test_safe_fixture_has_no_false_positives():
    cats = _categories(FIXTURES / "safe.py")
    leaked = [c for c in cats if c in (
        "open-redirect", "cors-misconfiguration", "auth-bypass", "idor",
        "path-traversal", "hardcoded-secret", "nosql-injection",
    )]
    assert not leaked, f"safe fixture falsely flagged: {cats}"


def test_cors_fixed_domain_not_reported():
    # safe.py uses allow_origins=["https://app.example.com"] — must not fire.
    cats = _categories(FIXTURES / "safe.py")
    assert "cors-misconfiguration" not in cats


def test_admin_route_with_depends_not_reported():
    cats = _categories(FIXTURES / "safe.py")
    assert "auth-bypass" not in cats


def test_idor_with_ownership_check_not_reported():
    cats = _categories(FIXTURES / "safe.py")
    assert "idor" not in cats


def test_empty_env_default_not_reported():
    # safe.py: os.environ.get("APP_SECRET", "") -> empty default must not fire.
    cats = _categories(FIXTURES / "safe.py")
    assert "hardcoded-secret" not in cats
