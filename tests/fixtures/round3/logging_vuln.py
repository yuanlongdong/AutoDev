"""Sensitive data in logs: password written via logger.info.

Plus a safe variant that logs a non-sensitive username only.
"""
import logging

logger = logging.getLogger("demo")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # VULN: password interpolated into a log line.
    logger.info(f"Login attempt for user: {username} with password: {password}")
    return "ok"


@app.route("/audit", methods=["POST"])
def audit():
    username = request.form.get("username", "")
    # SAFE: only the username is logged.
    logger.info("audit event for %s", username)
    return "ok"
