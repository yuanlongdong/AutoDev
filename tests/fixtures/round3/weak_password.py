"""Weak password policy: setter that accepts any non-empty password.

Plus a safe setter that enforces length + complexity.
"""
import re

from flask import request, session


@app.route("/change_password")
def change_password():
    new_password = request.args.get("password", "")
    # VULN: only "non-empty" is checked; no strength policy.
    if len(new_password) > 0:
        if "user_id" in session:
            user = User.query.get(session["user_id"])
            user.password = new_password
            db.session.commit()
            return "Password changed"
    return "Password change failed"


@app.route("/signup")
def signup():
    password = request.args.get("password", "")
    # SAFE: minimum length + mixed character classes enforced.
    if len(password) < 8 or not re.search(r"[A-Z]", password):
        return "password too weak", 400
    user = User(password=password)
    db.session.add(user)
    return "ok"
