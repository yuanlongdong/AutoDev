"""v0.4.0 round-5 – debug endpoint exposing environment / config secrets."""
import os
from flask import Flask, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret"
JWT_SECRET = "jwt-secret-value"


@app.route("/debug")
def debug():
    # VULNERABLE: returns the whole environment and config secrets.
    return jsonify({
        "environment": dict(os.environ),
        "secret": app.config["SECRET_KEY"],
        "jwt_secret": JWT_SECRET,
    })


@app.route("/health")
def health():
    # SAFE: returns a static status, no env / config material.
    return jsonify({"status": "running"})
