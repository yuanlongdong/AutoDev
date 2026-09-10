"""v0.5.2 fixture — open-redirect true/false positives.

* ``static_login``    — ``redirect(url_for("auth.login"))``  -> NOT reported
* ``static_dashboard``— ``redirect(url_for("profile.dashboard"))`` -> NOT reported
* ``literal_path``    — ``redirect("/login")``                -> NOT reported
* ``user_next``       — ``redirect(target)`` (request args)   -> reported
* ``dyn_endpoint``    — ``redirect(url_for(endpoint_var))``   -> reported
"""
from flask import Blueprint, redirect, url_for, request

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login")
def static_login():
    return redirect(url_for("auth.login"))


@auth_bp.route("/dashboard")
def static_dashboard():
    return redirect(url_for("profile.dashboard"))


@auth_bp.route("/stat")
def literal_path():
    return redirect("/login")


@auth_bp.route("/go")
def user_next():
    target = request.args.get("next", "/")
    return redirect(target)


@auth_bp.route("/dyn")
def dyn_endpoint():
    endpoint = request.args.get("ep")
    return redirect(url_for(endpoint))
