"""v0.4.0 round-5 – mass assignment via **request body unpacking."""
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/register", methods=["POST"])
def register():
    # VULNERABLE: all request.json keys expanded onto a new dict, incl. role.
    new_user = {
        "id": 1,
        **request.json,
    }
    return jsonify(new_user)


@app.route("/profile", methods=["POST"])
def update_profile():
    # VULNERABLE: **request.form unpacked into an object constructor.
    user = User(**request.form)
    return jsonify({"ok": user.id})


@app.route("/safe", methods=["POST"])
def safe_create():
    # SAFE: explicit whitelist of fields, no ** unpacking.
    data = request.json or {}
    user = User(username=data.get("username"), email=data.get("email"))
    return jsonify({"ok": True})


class User:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
