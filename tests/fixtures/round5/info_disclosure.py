"""v0.4.0 round-5 – information disclosure via errors / tracebacks."""
import traceback
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/db-error")
def db_error():
    try:
        # VULNERABLE: exception message embeds a connection string with creds.
        raise Exception("Database connection failed: mysql://admin:password@localhost:3306/mydb")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/boom")
def boom():
    try:
        1 / 0
    except ZeroDivisionError:
        # VULNERABLE: full traceback returned to the client.
        return jsonify({"traceback": traceback.format_exc()}), 500


@app.errorhandler(500)
def handle_500(e):
    # VULNERABLE: traceback printed / returned on the error handler.
    traceback.print_exc()
    return jsonify({"detail": traceback.format_exc()}), 500


@app.route("/safe-error")
def safe_error():
    try:
        1 / 0
    except ZeroDivisionError:
        # SAFE: generic message, no stack trace.
        return jsonify({"error": "internal error"}), 500
