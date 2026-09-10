"""Privilege escalation: destructive route operation without an admin check."""
from flask import Flask

app = Flask(__name__)


@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):
    # VULN: destructive operation on a caller-supplied id, no role check.
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return f"User {user.username} deleted"
    return "not found"


@app.route("/admin_delete/<int:user_id>")
def admin_delete(user_id):
    # SAFE: admin role required.
    if role != "admin":
        return "forbidden", 403
    user = User.query.get(user_id)
    db.session.delete(user)
    return "deleted"
