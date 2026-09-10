"""round-6 fixture: insecure configuration.

Module-level Flask debug setting, Django-style production debug flag and a
wildcard host allow-list must be reported as security-misconfiguration; a
function-local debug flag must not.
"""
from __future__ import annotations

from flask import Flask, request

app = Flask(__name__)

# VULN: Flask debug mode left on
app.config["DEBUG"] = True


# VULN: Django-style production debug / host allow-list
DEBUG = True
ALLOWED_HOSTS = ["*"]


def view():
    debug = True  # SAFE: function-local variable, must NOT be reported
    return debug
