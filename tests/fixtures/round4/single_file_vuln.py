"""A single, self-contained vulnerable module (SQL injection).

Used to prove that ``ResearchEngine`` / ``ASTResearchEngine`` accept a single
file path (not just a directory) and still report findings.
"""
from flask import Flask, request

app = Flask(__name__)


@app.route("/users")
def users():
    username = request.args.get("username")
    cursor = db_conn.cursor()
    # BAD: string-built SQL from request input
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchall()
