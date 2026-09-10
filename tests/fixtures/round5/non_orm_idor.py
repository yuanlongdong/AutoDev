"""v0.4.0 round-5 – non-ORM IDOR (list comprehension / next / dict lookup)."""
from flask import Flask, jsonify

app = Flask(__name__)
users = []


@app.route("/api/users/<int:user_id>")
def get_user(user_id):
    # VULNERABLE: next() over a generator filtering by the route id, no authz.
    user = next((u for u in users if u["id"] == user_id), None)
    return jsonify(user)


@app.route("/api/people/<int:person_id>")
def list_people(person_id):
    # VULNERABLE: list comprehension filtering by the route id, no authz.
    matches = [u for u in users if u["id"] == person_id]
    return jsonify(matches)


@app.route("/api/items/<int:item_id>")
def lookup_item(item_id):
    # VULNERABLE: dict lookup keyed by the route id, no authz.
    return jsonify(store[item_id])


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    # VULNERABLE: list rebuild (!=) by route id → privilege escalation.
    global users
    users = [u for u in users if u["id"] != user_id]
    return jsonify({"deleted": True})


@app.route("/api/owned/<int:doc_id>")
def owned_doc(doc_id):
    # SAFE: ownership check present.
    doc = next((d for d in docs if d["id"] == doc_id), None)
    if doc and doc["owner_id"] == current_user.id:
        return jsonify(doc)
    return jsonify({"error": "forbidden"}), 403


store = {}
docs = []


class _Current:
    id = 1


current_user = _Current()
