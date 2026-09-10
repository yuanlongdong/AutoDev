"""v0.5.0 – FastAPI *safe* sample (static AST fixture, not executed).

Each handler above is remediated: no open redirect, locked-down CORS, admin
route protected by a dependency, IDOR guarded by an ownership check, path
traversal contained, no hardcoded fallback secret, and no raw request body
forwarded to a database driver.
"""
from fastapi import FastAPI, Request, Depends
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# CORS: fixed trusted origin only — safe (no wildcard, no credentials leak)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
    allow_methods=["GET"],
)

# secret: empty / non-secret default — safe
SESSION_SECRET = os.environ.get("APP_SECRET", "")
PORT = os.environ.get("APP_PORT", "8080")


def current_user(authorization: str = ""):
    return {"id": 1, "username": "alice"}


# admin route protected by Depends
@app.get("/api/admin/users")
def admin_list_users(user=Depends(current_user)):
    rows = db.execute("SELECT * FROM users")
    return rows


# redirect to a fixed, allowlisted literal path
@app.get("/api/redirect")
def redirect(next: str):
    return RedirectResponse(url="/home")


# IDOR guarded: ownership verified before returning
@app.get("/api/notes/{note_id}")
def get_note(note_id: int, user=Depends(current_user)):
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row["owner_id"] != user["id"]:
        raise HTTPException(status_code=403)
    return dict(row)


# path traversal contained: name is restricted to a basename
@app.get("/api/files")
def get_file(name: str):
    name = os.path.basename(name)
    path = os.path.join("/uploads", name)
    return FileResponse(path)


# NoSQL: request body fully validated; only allowlisted keys are used.
@app.post("/find")
async def nosql_find(request: Request):
    body = await request.json()
    username = body.get("username", "")
    if not re.match(r"^[a-z0-9_]+$", username):
        raise HTTPException(status_code=400)
    # validated value is re-encoded into a constant query shape; the raw
    # request dict is never forwarded to the driver.
    return {"username": username, "ok": True}
