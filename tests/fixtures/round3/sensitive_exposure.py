"""Sensitive data exposure: card number / ssn from request, persisted and echoed.

Plus a safe variant that stores only a non-sensitive reference.
"""
from flask import request


@app.route("/store_sensitive")
def store_sensitive():
    credit_card = request.args.get("cc", "4111111111111111")
    ssn = request.args.get("ssn", "123-45-6789")
    # VULN: persisted via ORM in plain text...
    payment = Payment(user_id=1, amount=100.0, card_number=credit_card)
    db.session.add(payment)
    db.session.commit()
    # ...and echoed back in the response.
    return f"Stored credit card: {credit_card}, SSN: {ssn}"


@app.route("/safe_store")
def safe_store():
    token = request.args.get("token", "")
    # SAFE: a one-way reference is returned, not the raw sensitive value.
    ref = hashlib.sha256(token.encode()).hexdigest()
    return f"Stored reference: {ref}"
