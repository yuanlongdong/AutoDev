"""Two-step XSS — MUST NOT be reported.

The f-string HTML interpolates a value that comes from the database, which the
existing taint model treats as provably safe.  Assignment + return alone is not
enough; the interpolated root must be attacker-controlled.
"""


def show_profile(request):
    """DB row rendered as HTML — safe output."""
    db_result = db.query.get(1)
    html = f"<div>{db_result}</div>"
    return HttpResponse(html)


def list_items(request):
    """Another DB-backed two-step shape — safe output."""
    rows = db.session.query(Item).all()
    html = "".join([f"<li>{r.name}</li>" for r in rows])
    return HttpResponse(html)
