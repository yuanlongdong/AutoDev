"""Safe functions that must NOT trigger IDOR / authz-family findings.

Every handler below performs an explicit authorization check, so the
IDOR / privilege-escalation detectors must stay silent.
"""
from flask import session, current_user


@app.route("/profile/<int:user_id>")
def profile(user_id):
    # SAFE: session ownership check.
    if session["user_id"] != user_id:
        return "forbidden", 403
    user = User.query.get(user_id)
    return f"{user.username}"


@app.route("/notes/<int:note_id>")
def note(note_id):
    # SAFE: current_user + ownership helper.
    note = Note.query.get(note_id)
    if not is_owner(note, current_user):
        return "forbidden", 403
    return note.body


@app.route("/admin/users/<int:user_id>")
@login_required
def admin_user(user_id):
    # SAFE: login_required decorator + role check.
    if role == "admin":
        user = User.query.get(user_id)
        return user.username
    return "forbidden", 403
