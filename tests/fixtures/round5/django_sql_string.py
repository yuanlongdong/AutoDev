"""v0.4.0 round-5 – f-string SQL constructed without an execute() call."""
from flask import Flask, request

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    # VULNERABLE: dynamic SQL built as a string, never parameterised.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(query)
    return {"ok": True}


@app.route("/query", methods=["POST"])
def run_query():
    table = request.json.get("table", "users")
    # VULNERABLE: printf-% interpolation into SQL.
    sql = "SELECT * FROM %s WHERE id = %s" % (table, 1)
    return {"sql": sql}


@app.route("/safe", methods=["POST"])
def safe_login():
    username = request.form.get("username")
    # SAFE: parameterised query with placeholders.
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return {"ok": True}
