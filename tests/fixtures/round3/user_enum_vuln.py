"""User enumeration: distinct error messages leak which usernames exist.

Plus a safe login that returns a single generic message.
"""
from flask import request


@app.route("/brute_force_login", methods=["POST"])
def brute_force_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user = User.query.filter_by(username=username, password=password).first()
    if user:
        return "Login successful"
    else:
        existing = User.query.filter_by(username=username).first()
        if existing:
            return "Wrong password"      # leaks that the user exists
        else:
            return "User does not exist"  # leaks that the user does not


@app.route("/safe_login", methods=["POST"])
def safe_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    user = User.query.filter_by(username=username, password=password).first()
    if user:
        return "Login successful"
    # SAFE: single generic message for both unknown user and wrong password.
    return "Invalid credentials"
