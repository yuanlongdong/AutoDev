"""v0.4.0 round-5 – unrestricted file upload (no type allowlist) + safe upload."""
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload_file():
    # VULNERABLE: request.files + .save() but only secure_filename, no type check.
    file = request.files["file"]
    filename = secure_filename(file.filename)
    file.save("/tmp/uploads/" + filename)
    return {"ok": True}


@app.route("/upload-avatar", methods=["POST"])
def upload_avatar():
    file = request.files["avatar"]
    # VULNERABLE: no extension / content-type validation at all.
    file.save("/tmp/avatars/" + file.filename)
    return {"ok": True}


ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}


@app.route("/safe-upload", methods=["POST"])
def safe_upload():
    file = request.files["file"]
    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[-1].lower()
    # SAFE: genuine extension allowlist present.
    if ext not in ALLOWED_EXTENSIONS:
        return {"error": "forbidden"}, 400
    file.save("/tmp/safe/" + filename)
    return {"ok": True}


@app.route("/typed-upload", methods=["POST"])
def typed_upload():
    file = request.files["file"]
    # SAFE: content-type + endswith check present.
    if not file.filename.endswith((".jpg", ".png", ".pdf")):
        return {"error": "type"}, 400
    file.save("/tmp/typed/" + secure_filename(file.filename))
    return {"ok": True}
