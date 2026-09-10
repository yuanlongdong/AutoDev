"""IDOR: vulnerable handler without authz + a safe handler with an ownership check."""
from flask import Flask

app = Flask(__name__)


@app.route("/user/<int:user_id>")
def user_profile(user_id):
    # VULN: caller-supplied id, no ownership / session check.
    user = User.query.get(user_id)
    if user:
        return f"<h1>{user.username}</h1>"
    return "not found"


@app.route("/documents/<int:doc_id>")
def view_document(doc_id):
    # VULN: caller-supplied doc id, no authz.
    document = Document.query.get(doc_id)
    if document:
        return f"<h1>{document.filename}</h1>"
    return "not found"


@app.route("/safe_profile/<int:user_id>")
def safe_profile(user_id):
    # SAFE: ownership is verified against the session.
    if session.get("user_id") != user_id:
        return "forbidden", 403
    user = User.query.get(user_id)
    return f"<h1>{user.username}</h1>"


@app.route("/owned/<int:order_id>")
def owned_order(order_id):
    # SAFE: ownership check present.
    order = Order.query.get(order_id)
    if not is_owner(order, current_user):
        return "forbidden", 403
    return f"{order.total}"
