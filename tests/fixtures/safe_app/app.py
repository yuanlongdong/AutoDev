"""Safe sample application for testing false-positive avoidance.

Contains the same operations as the vulnerable app but with proper
sanitization, parameterization, and authorization.
"""
import os
import hashlib
import yaml
from flask import Flask, request, redirect, render_template, send_file
from werkzeug.utils import secure_filename
from markupsafe import escape

app = Flask(__name__)

# Secret loaded from environment, not hardcoded
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
app.config["DEBUG"] = False

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}


@app.route("/user")
def get_user():
    """Safe: parameterized query."""
    user_id = request.args.get("id")
    db.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return "ok"


@app.route("/ping")
def ping():
    """Safe: subprocess with argv list, no shell."""
    host = request.args.get("host")
    subprocess.run(["ping", "-c", "1", host], shell=False)
    return "done"


@app.route("/download")
def download():
    """Safe: path constrained to allowlisted directory."""
    filename = secure_filename(request.args.get("file"))
    safe_path = os.path.join("/var/data/", filename)
    if not safe_path.startswith("/var/data/"):
        return "invalid", 400
    return send_file(safe_path)


@app.route("/greet")
def greet():
    """Safe: output escaped via MarkupSafe."""
    name = escape(request.args.get("name", ""))
    return render_template("greet.html", name=name)


@app.route("/load")
def load_data():
    """Safe: JSON instead of pickle."""
    import json
    data = json.loads(request.data)
    return str(data)


@app.route("/config")
def load_config():
    """Safe: yaml.safe_load."""
    config = request.args.get("config")
    return yaml.safe_load(config)


@app.route("/redirect")
def do_redirect():
    """Safe: redirect URL validated."""
    target = request.args.get("next")
    if not is_safe_url(target):
        return "invalid redirect", 400
    return redirect(target)


@app.route("/upload", methods=["POST"])
def upload():
    """Safe: secure_filename + extension check."""
    f = request.files["file"]
    filename = secure_filename(f.filename)
    if "." not in filename or filename.rsplit(".", 1)[1].lower() not in ALLOWED_EXTENSIONS:
        return "invalid file", 400
    f.save(os.path.join("/uploads/", filename))
    return "uploaded"


@app.route("/hash")
def hash_password():
    """Safe: SHA-256 with salt."""
    pw = request.args.get("pw")
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 100000).hex()


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    """Safe: admin route requires auth + admin role."""
    return db.execute("SELECT * FROM users").fetchall()


@app.route("/order/<int:order_id>")
@login_required
def get_order(order_id):
    """Safe: ownership check."""
    order = db.execute("SELECT * FROM orders WHERE id = %s", (order_id,)).fetchone()
    if order["user_id"] != current_user.id:
        return "forbidden", 403
    return order


def is_safe_url(target):
    from urllib.parse import urlparse
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc
