"""Business logic flaw: transfer accepting a negative amount.

Plus a safe transfer that rejects non-positive amounts.
"""
from flask import request


@app.route("/transfer_funds")
def transfer_funds():
    from_account = request.args.get("from", "")
    to_account = request.args.get("to", "")
    amount = float(request.args.get("amount", 0))
    # VULN: only "non-zero" is checked, so negative amounts are accepted.
    if amount != 0:
        return f"Transferred ${amount} from {from_account} to {to_account}"
    return "Invalid transfer"


@app.route("/safe_transfer")
def safe_transfer():
    from_account = request.args.get("from", "")
    to_account = request.args.get("to", "")
    amount = float(request.args.get("amount", 0))
    # SAFE: non-positive amounts are explicitly rejected.
    if amount <= 0:
        return "Amount must be positive", 400
    return f"Transferred ${amount}"
