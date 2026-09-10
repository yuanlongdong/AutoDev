"""SSRF safe fixture — requests.get(user_id) must NOT be reported as SSRF."""
import requests
from flask import request


def get_user(user_id):
    # user_id is a database identifier, not a URL
    resp = requests.get(f"http://internal-api/users/{user_id}")
    return resp.json()


def get_doc(doc_id):
    # doc_id is a document identifier, not a URL
    return requests.get(doc_id)
