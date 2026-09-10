"""Security misconfiguration: app.run with debug=True and a wildcard bind.

Also contains a safe variant (production bind + debug off) and a decoy that
must NOT match (``DEBUG = True`` assignment / ``app.config``).
"""
from flask import Flask

app = Flask(__name__)

DEBUG = True  # decoy: module-level assignment must not be reported

app.config["DEBUG"] = True  # decoy: config assignment must not be reported


@app.route("/")
def index():
    return "ok"


if __name__ == "__main__":
    # VULN: debugger exposed + bound on all interfaces.
    app.run(host="0.0.0.0", port=5000, debug=True)
