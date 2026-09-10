"""v0.6.0 – SSRF false-positive fixtures.

``sync_products``  — URL from an env/config constant (MUST NOT be reported).
``proxy_request``  — URL built from request input (SHOULD be reported).
"""
import os
import requests
from flask import request

PRODUCT_SERVICE_URL = os.environ.get("PRODUCT_SERVICE_URL", "http://product-service:8082")


def sync_products():
    response = requests.get(f"{PRODUCT_SERVICE_URL}/api/products/", timeout=10)
    return response.json()


def proxy_request():
    target = request.args.get("url")
    return requests.get(target, timeout=10).text
