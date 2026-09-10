"""Reflected / stored XSS via f-string HTML — must be detected."""
from flask import request


def hello():
    name = request.args.get("name", "")
    return f"<h1>Hello {name}!</h1>"


def search_results(results):
    items = "".join([f"<li>{q}</li>" for q in results])
    return f"<ul>{items}</ul>"


def profile():
    user = request.args.get("user", "")
    return f"<div class='profile'><span>{user}</span></div>"
