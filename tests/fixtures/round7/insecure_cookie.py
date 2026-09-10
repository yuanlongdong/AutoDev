"""Round-7 insecure-cookie fixture: vulnerable + safe variants."""
from flask import make_response


def bad_cookie_explicit_flags():
    """BAD: httponly=False and secure=False set explicitly."""
    resp = make_response("ok")
    resp.set_cookie('session_id', 'abc', httponly=False, secure=False)
    return resp


def bad_cookie_missing_flags():
    """BAD: no httponly / secure argument at all (both default off)."""
    resp = make_response("ok")
    resp.set_cookie('session_id', 'abc')
    return resp


def good_cookie_flags():
    """SAFE: both protective flags explicitly enabled."""
    resp = make_response("ok")
    resp.set_cookie('session_id', 'abc', httponly=True, secure=True, samesite='Lax')
    return resp


def django_style_bad(request):
    """BAD: Django-style HttpResponse.set_cookie with weak flags."""
    response = request
    response.set_cookie('session_id', 'xyz', httponly=False, secure=False)
    return response
