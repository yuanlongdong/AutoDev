"""v0.6.0 – TOCTOU / race-condition fixture.

``withdraw``        — check-then-act on balance with no transaction (VULNERABLE)
``redeem_coupon``   — check-then-act on a used flag with no lock (VULNERABLE)
``withdraw_safe``   — protected by BEGIN ... COMMIT (SAFE)
``list_users``      — read-only, not a financial operation (SAFE)
"""
from flask import Blueprint, request, jsonify

bp = Blueprint("bank", __name__)


@bp.post("/withdraw")
def withdraw():
    db = request.environ["db"]
    amount = int(request.form.get("amount", 0))
    user = db.execute("SELECT balance FROM users WHERE id = ?", (1,)).fetchone()
    if user["balance"] < amount:
        return jsonify({"error": "insufficient"}), 400
    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, 1))
    db.commit()
    return jsonify({"ok": True})


@bp.post("/coupon")
def redeem_coupon():
    db = request.environ["db"]
    row = db.execute("SELECT used FROM coupons WHERE code = ?", ("F100",)).fetchone()
    if row["used"] == 1:
        return jsonify({"error": "used"}), 400
    db.execute("UPDATE coupons SET used = 1 WHERE code = ?", ("F100",))
    db.commit()
    return jsonify({"ok": True})


@bp.post("/withdraw_safe")
def withdraw_safe():
    db = request.environ["db"]
    amount = int(request.form.get("amount", 0))
    db.execute("BEGIN")
    user = db.execute("SELECT balance FROM users WHERE id = ?", (1,)).fetchone()
    if user["balance"] < amount:
        db.rollback()
        return jsonify({"error": "insufficient"}), 400
    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, 1))
    db.commit()
    return jsonify({"ok": True})


@bp.get("/users")
def list_users():
    db = request.environ["db"]
    rows = db.execute("SELECT id, name FROM users").fetchall()
    return jsonify(rows)
