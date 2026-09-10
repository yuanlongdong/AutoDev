"""v0.5.1 — SQL injection via SQLAlchemy ``text()``.

``text()`` is SQLAlchemy's raw-SQL constructor.  When its argument is built
from user input via ``%`` formatting / f-string / ``.format()`` / ``+`` it is
an injection; a pure static literal (even one with named bind params like
``:name``) is parameterised and must not be reported.
"""
from sqlalchemy import text


def search_percent(filter):
    """BAD: printf-% formatting of a user value inside text()."""
    return text("title = '%s' or content = '%s'" % (filter, filter))


def search_fstring(name):
    """BAD: f-string interpolation inside text()."""
    return text(f"SELECT * FROM users WHERE name = {name}")


def search_format(name):
    """BAD: .format() interpolation inside text()."""
    return text("SELECT * FROM users WHERE name = {}".format(name))


def search_concat(name):
    """BAD: string concatenation inside text()."""
    return text("SELECT * FROM users WHERE name = " + name)
