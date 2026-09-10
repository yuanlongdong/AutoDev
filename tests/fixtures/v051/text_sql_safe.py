"""v0.5.1 — safe ``text()`` usage that must NOT be flagged.

* a pure static string literal;
* a static literal with a named SQLAlchemy bind parameter (``:name``) — this
  is the canonical parameterised pattern and takes the value via a separate
  ``params(...)`` call, never via string interpolation.
"""
from sqlalchemy import text


def static_query():
    """SAFE: no interpolation at all."""
    return text("SELECT 1")


def named_bind(name):
    """SAFE: named bind parameter, value passed separately at execute time."""
    return text("SELECT * FROM users WHERE name = :name")


def parameterized_percent_literal(cur):
    """SAFE: static %s placeholder fed through execute with a params tuple."""
    return cur.execute("SELECT * FROM users WHERE name = %s", (name,))
