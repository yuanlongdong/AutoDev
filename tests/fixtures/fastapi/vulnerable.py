"""v0.5.0 – FastAPI vulnerable sample (static AST fixture, not executed).

Mirrors the patterns found on the two FastAPI shooting ranges.  Every handler
uses FastAPI route-handler parameters (no ``request.args`` attribute access),
which is exactly why the v0.4.x structured detectors missed them.
"""
from fastapi import FastAPI, Request, Depends
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# 2. CORS misconfiguration — wildcard + credentials (module level)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 6. hardcoded secret defaults in os.environ.get
SESSION_SECRET = os.environ.get("APP_SECRET", "sup3r-s3cr3t-signing-key-do-not-share")
STRIPE_KEY = os.environ.get("APP_STRIPE", "sk_test_51QpLaYgr0uNd00example00key")


def current_user(authorization: str = ""):
    return {"id": 1, "username": "alice"}


def mongo_lookup(query):
    return db.users.find(query)


# 3. auth bypass — admin route, no Depends
@app.get("/api/admin/users")
def admin_list_users():
    rows = db.execute("SELECT * FROM users")
    return rows


# 1. open redirect — RedirectResponse(url=next)
@app.get("/api/redirect")
def redirect(next: str):
    return RedirectResponse(url=next)


# 4. IDOR — path id used in a lookup, authenticated but no ownership check
@app.get("/api/notes/{note_id}")
def get_note(note_id: int, user=Depends(current_user)):
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    return dict(row)


# 5. path traversal — query param flows into FileResponse via os.path.join
@app.get("/api/files")
def get_file(name: str):
    path = os.path.join("/uploads", name)
    return FileResponse(path)


# 7a. NoSQL injection — request.json() forwarded to a mongo helper
@app.post("/find")
async def nosql_find(request: Request):
    query = await request.json()
    return mongo_lookup(query)


# 7b. NoSQL injection — GET route param forwarded to a mongo helper
@app.get("/find")
async def nosql_get(username: str):
    return mongo_lookup({"username": username})
