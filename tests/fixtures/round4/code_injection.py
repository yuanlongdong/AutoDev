"""Code injection via eval/exec (v0.3.1 bug 3).

``eval(data)`` / ``exec(user_input)`` are reachable from request input and must
be reported; ``eval("1+1")`` is a static literal and must *not* be reported.
"""
from flask import Flask, request

app = Flask(__name__)


@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.form.get("payload")
    obj = eval(data)  # BAD: request-controlled string evaluated
    return {"obj": str(obj)}


@app.route("/run", methods=["POST"])
def run():
    user_input = request.form.get("code")
    exec(user_input)  # BAD: request-controlled string executed
    return {"ok": True}


def safe_eval():
    # static string literal — must NOT be reported
    return eval("1+1")
