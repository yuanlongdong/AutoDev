"""SSTI safe fixture — static template with context var must NOT be reported."""
from flask import render_template_string, request


def hello():
    name = request.args.get("name", "")
    # Static template string; name is passed as context — safe
    return render_template_string("Hello {{ name }}", name=name)
