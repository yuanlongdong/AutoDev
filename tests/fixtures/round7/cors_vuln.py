"""Round-7 CORS fixture: vulnerable + safe variants."""
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route('/cors_bad')
def cors_reflect_origin():
    """BAD: reflect the attacker-supplied Origin header and allow credentials."""
    origin = request.headers.get('Origin', '*')
    response = jsonify({'data': 'sensitive'})
    response.headers['Access-Control-Allow-Origin'] = origin
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


@app.route('/cors_static')
def cors_static_origin():
    """SAFE: fixed, trusted origin (not a literal wildcard)."""
    response = jsonify({'data': 'ok'})
    response.headers['Access-Control-Allow-Origin'] = 'https://trusted.example.com'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


@app.route('/cors_star')
def cors_wildcard_with_creds():
    """BAD: wildcard origin combined with credentials."""
    response = jsonify({'data': 'sensitive'})
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


# BAD: Flask-CORS initialised with wildcard origins.
def configure_cors():
    CORS(app, resources={r"/*": {"origins": "*"}})
