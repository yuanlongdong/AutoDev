"""Two-step XSS — f-string HTML assigned to a variable, then returned.

The f-string uses a single-quoted HTML attribute (``class='message'``), which
the v0.4.3 line-oriented ``_FSTRING_HTML`` regex could not see through.  The
interpolated value flows from ``request.GET``, so the two-step detector must
report the assignment line.
"""


def format_message(request):
    """XSS via format string (two-step)."""
    message = request.GET.get('msg', '')
    # BAD: user input interpolated into HTML, stored in a variable, then returned
    html = f"<div class='message'>{message}</div>"
    return HttpResponse(html)


def bare_return(request):
    """Same two-step shape, bare ``return html_var``."""
    q = request.args.get('q', '')
    html = f"<p>{q}</p>"
    return html
