"""Two-step XSS — MUST NOT be reported.

The assigned value is a *static* HTML string literal with no interpolation, so
there is no attacker-controlled content to escape.  This must not be flagged as
an f-string / dynamic HTML finding.
"""


def static_page(request):
    """Fully static HTML body."""
    html = "<h1>Static</h1>"
    return HttpResponse(html)


def also_static(request):
    """Static HTML built from a plain (non-f) string."""
    heading = "<div class='banner'>Welcome</div>"
    return HttpResponse(heading)
