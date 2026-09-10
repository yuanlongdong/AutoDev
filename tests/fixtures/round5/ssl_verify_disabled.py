"""v0.4.0 round-5 – disabled SSL certificate verification."""
import ssl
import urllib3
import requests


def fetch(url):
    # VULNERABLE: requests.get with verify=False.
    return requests.get(url, verify=False)


def post_insecure(url, data):
    # VULNERABLE: requests.post with verify=False.
    return requests.post(url, json=data, verify=False)


def disable_warnings():
    # VULNERABLE: urllib3 warnings disabled (paired with verify=False).
    urllib3.disable_warnings()
    return requests.get("https://example.com", verify=False)


def unverified_context():
    # VULNERABLE: unverified SSL context.
    ctx = ssl._create_unverified_context()
    return ctx


def secure_get(url):
    # SAFE: default verification on.
    return requests.get(url, timeout=5)
