"""True-positive XSS fixtures — all three must be reported.

Covers the three source classes the v0.2.2 taint model is meant to catch:
  * request query-string input (``request.args.get``)
  * a route-handler parameter (``@app.route`` → parameter is tainted)
  * stored / session input (``session.get``)
"""
from flask import request, session


def reflected():
    name = request.args.get("name", "")
    # tainted request input rendered as HTML
    return f"<h1>Hello {name}!</h1>"


def handler_param(name):
    # ``name`` is a route-handler parameter → tainted
    return f"<h1>Hello {name}!</h1>"


def stored():
    q = session.get("q", "")
    # tainted session input rendered as HTML
    items = "".join([f"<li>{q}</li>" for _ in range(1)])
    return f"<ul>{items}</ul>"
