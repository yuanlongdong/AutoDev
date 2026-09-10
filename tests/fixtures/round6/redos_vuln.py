"""round-6 fixture: ReDoS detection.

A nested-quantifier regex applied to request input must be reported; a plain
regex with no nested quantifier must not.
"""
from __future__ import annotations

import re
from flask import request


def validate_email():
    email = request.json.get("email", "")
    pattern = r"^([a-zA-Z0-9_.\-])+@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$"
    return bool(re.match(pattern, email))  # BAD: nested quantifier on user input


def validate_plain():
    name = request.json.get("name", "")
    pattern = r"^[a-zA-Z0-9_]+$"  # SAFE: no group / no nested quantifier
    return bool(re.match(pattern, name))
