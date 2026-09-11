"""v0.7.0 fixtures: Bottle request sources + template() SSTI."""
from bottle import request, template, get_template


def help_view():
    # User-controlled template source read off disk then handed to template()
    vuln = request.query.get('vuln')
    html = open('./help/' + vuln + '.md').read()
    temp = get_template('_help', instructions=html)
    return template(temp)


def login_view():
    # Static template name + tainted context value — safe, must not SSTI
    user = request.forms.get('username')
    return template('login.html', user=user)


def profile_view():
    # Bottle query param flowing into a context variable
    level = request.params.get('level')
    return template('profile.html', level=level)
