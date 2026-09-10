"""Import lines must NOT be flagged as XSS or other regex findings."""
from flask import render_template_string, Markup, mark_safe
import requests
from ldap3 import Connection
import xml.etree.ElementTree as ET
import jwt

SECRET_KEY = "static-not-a-secret"
