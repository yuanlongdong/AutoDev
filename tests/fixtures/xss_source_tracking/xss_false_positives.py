"""False-positive XSS fixtures — none of these must be reported.

Each f-string interpolates a value that is provably NOT attacker-controlled:
  * database rows (``Model.query.get`` / ``.all``)
  * hash / encoding results (``hashlib.*`` / ``base64.*``)
  * command-execution output (``subprocess.check_output``)
  * a static template passed to ``render_template_string`` with context vars
"""
import hashlib
import base64
import subprocess
from flask import render_template_string


def db_row(uid):
    user = User.query.get(uid)
    # ``user`` is a database row, not user-controlled HTML
    return f"<p>Username: {user.username}</p>"


def db_list():
    users = User.query.all()
    rows = [u.username for u in users]
    return f"<p>Users: {rows}</p>"


def hash_output(password):
    h = hashlib.md5(password.encode()).hexdigest()
    return f"<p>Digest: {h}</p>"


def encoded_output(raw):
    enc = base64.b64encode(raw).decode()
    return f"<p>Encoded: {enc}</p>"


def command_output(cmd):
    result = subprocess.check_output(cmd)
    return f"<pre>{result.decode()}</pre>"


def static_template(name):
    # static template source; variables passed as context — safe
    template = "<h1>Hello {{ name }}!</h1>"
    return render_template_string(template, name=name)
