"""round-6 fixture: marshal deserialization."""
from __future__ import annotations

import marshal
from flask import request


def use_marshal():
    data = request.get_data()
    obj = marshal.loads(data)  # BAD: untrusted marshal input
    return obj
