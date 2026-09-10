"""Vulnerable sample application for testing the vulnerability researcher.

This file intentionally contains multiple security flaws.  It is NEVER
executed by the tool – it exists only as static analysis input.
"""
import os
import pickle
import subprocess
import hashlib
import yaml
from flask import Flask, request, redirect, render_template_string, send_file

app = Flask(__name__)
app.config["SECRET_KEY"] = "hardcoded-super-secret-key-12345"
app.config["DEBUG"] = True

# Hardcoded database credentials
DB_PASSWORD = "admin123!"
API_TOKEN = "sk-live-abcdefghijklmnopqrstuvwxyz"


@app.route("/user")
def get_user():
    """SQL Injection: user input directly concatenated into query."""
    user_id = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_id
    db.execute(query)
    return query


@app.route("/search")
def search():
    """SQL Injection via f-string."""
    term = request.args.get("q")
    db.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return "ok"


@app.route("/ping")
def ping():
    """Command Injection."""
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "done"


@app.route("/exec")
def exec_cmd():
    """Command Injection via subprocess with shell=True."""
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True)
    return "done"


@app.route("/download")
def download():
    """Path Traversal / Arbitrary File Read."""
    filename = request.args.get("file")
    return send_file("/var/data/" + filename)


@app.route("/read")
def read_file():
    """Path Traversal via open()."""
    path = request.args.get("path")
    with open(path, "r") as f:
        return f.read()


@app.route("/fetch")
def fetch_url():
    """SSRF: user-controlled URL."""
    url = request.args.get("url")
    import requests
    return requests.get(url).text


@app.route("/greet")
def greet():
    """XSS / SSTI: user input in template string."""
    name = request.args.get("name")
    template = "<h1>Hello " + name + "</h1>"
    return render_template_string(template)


@app.route("/load")
def load_data():
    """Dangerous Deserialization: pickle."""
    data = request.data
    obj = pickle.loads(data)
    return str(obj)


@app.route("/config")
def load_config():
    """Unsafe YAML deserialization."""
    config = request.args.get("config")
    return yaml.load(config)


@app.route("/redirect")
def do_redirect():
    """Open Redirect."""
    target = request.args.get("next")
    return redirect(target)


@app.route("/upload", methods=["POST"])
def upload():
    """Unrestricted File Upload."""
    f = request.files["file"]
    f.save("/uploads/" + f.filename)
    return "uploaded"


@app.route("/write")
def write_file():
    """Arbitrary File Write."""
    path = request.args.get("path")
    content = request.args.get("content")
    with open(path, "w") as f:
        f.write(content)
    return "written"


@app.route("/hash")
def hash_password():
    """Weak Cryptography: MD5."""
    pw = request.args.get("pw")
    return hashlib.md5(pw.encode()).hexdigest()


@app.route("/admin/users")
def admin_users():
    """Admin API without authentication."""
    return db.execute("SELECT * FROM users").fetchall()


@app.route("/api/internal/debug")
def internal_debug():
    """Internal API exposed without auth."""
    return {"env": dict(os.environ)}


@app.route("/order/<int:order_id>")
def get_order(order_id):
    """IDOR: no ownership check."""
    order = db.execute(f"SELECT * FROM orders WHERE id = {order_id}").fetchone()
    return order


@app.route("/profile", methods=["POST"])
def update_profile():
    """Only authenticated, no authorization check."""
    user_id = request.form.get("user_id")
    db.execute(f"UPDATE users SET email = '{request.form.get('email')}' WHERE id = {user_id}")
    return "updated"


def process_payment(order_id, amount):
    """Business logic: no state check before charging."""
    order = db.execute(f"SELECT * FROM orders WHERE id={order_id}").fetchone()
    charge_customer(order["customer_id"], amount)
    db.execute(f"UPDATE orders SET status='paid' WHERE id={order_id}")
    return "paid"


def unsafe_login(username, password):
    """Authentication bypass: SQL injection in login."""
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = db.execute(query).fetchone()
    if user:
        return "logged in"
    return "invalid"
