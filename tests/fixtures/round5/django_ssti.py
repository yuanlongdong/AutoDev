"""v0.4.0 round-5 – Django Template SSTI patterns."""
from django.http import HttpResponse
from django.template import Template, Context
from django.shortcuts import render


def greet(request):
    name = request.GET.get("name", "Guest")
    # VULNERABLE: f-string fed straight into Template().
    template = Template(f"<h1>Hello, {name}!</h1>")
    return HttpResponse(template.render(Context({})))


def render_dynamic(request):
    template_string = request.GET.get("template", "{{ name }}")
    # VULNERABLE: user-controlled string used as the template source.
    template = Template(template_string)
    return HttpResponse(template.render(Context({"name": "x"})))


def static_template(request):
    # SAFE: a static string literal template, no interpolation.
    template = Template("<h1>Hello World</h1>")
    return HttpResponse(template.render(Context({})))
