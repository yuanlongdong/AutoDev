"""v0.6.0 – SQL injection false-positive fixtures.

``safe_coupon_redeem`` — parameterised ``?`` with ``balance + ?`` arithmetic
                         (MUST NOT be reported: parameterised query).
``safe_transfer``       — parameterised ``?`` with ``balance - ?`` arithmetic
                         (MUST NOT be reported).
``vulnerable``          — f-string interpolation into SQL (SHOULD be reported).
"""
import sqlite3
from flask import request


def safe_coupon_redeem():
    db = sqlite3.connect(":memory:")
    reward = int(request.form.get("reward", 0))
    user_id = int(request.form.get("user_id", 1))
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (reward, user_id))
    db.commit()


def safe_transfer():
    db = sqlite3.connect(":memory:")
    amount = int(request.form.get("amount", 0))
    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, 1))
    db.commit()


def vulnerable():
    db = sqlite3.connect(":memory:")
    name = request.args.get("name")
    db.execute("SELECT * FROM users WHERE name = '" + name + "'")
