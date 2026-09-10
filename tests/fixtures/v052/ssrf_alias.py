"""v0.5.2 fixture — SSRF via aliased ``import requests as req``.

Contains four handlers:

* ``webhook``       — ``req.post(callback_url, ...)``               -> SSRF
* ``fetch``         — ``req.get(url, ...)``                        -> SSRF
* ``notify``        — ``req.post(data, ...)`` where ``data`` has no
                      network semantics                           -> NOT SSRF
* ``from_alias``    — ``from requests import get as g; g(url)``    -> SSRF
"""
from flask import Blueprint, request

tools_bp = Blueprint("tools", __name__)


@tools_bp.route("/tools/webhook", methods=["POST"])
def webhook():
    callback_url = request.form.get("url", "")
    import requests as req
    req.post(callback_url, json={"status": "ok"}, timeout=3)
    return "ok"


@tools_bp.route("/tools/fetch", methods=["POST"])
def fetch():
    url = request.form.get("url", "")
    import requests as req
    req.get(url, timeout=5)
    return "ok"


@tools_bp.route("/tools/notify", methods=["POST"])
def notify():
    data = request.form.get("payload", "")
    import requests as req
    req.post(data, timeout=3)
    return "ok"


@tools_bp.route("/tools/fromalias", methods=["POST"])
def from_alias():
    url = request.form.get("url", "")
    from requests import get as g
    g(url, timeout=5)
    return "ok"
