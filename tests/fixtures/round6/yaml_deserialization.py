"""round-6 fixture: YAML deserialization.

``yaml.load`` with the default / unsafe Loader and a request-derived argument
must be reported; ``yaml.safe_load`` must not.
"""
from __future__ import annotations

import yaml
from flask import request


def parse_yaml_user():
    data = request.json.get("yaml", "")
    cfg = yaml.load(data)  # BAD: no SafeLoader, request-derived input
    return cfg


def parse_yaml_unsafe_loader():
    data = request.data
    cfg = yaml.load(data, Loader=yaml.Loader)  # BAD: unsafe Loader
    return cfg


def parse_yaml_safe():
    data = request.data
    cfg = yaml.safe_load(data)  # SAFE: safe_load
    return cfg
