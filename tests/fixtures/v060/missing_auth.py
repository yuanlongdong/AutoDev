"""v0.6.0 – missing-authentication fixture (FastAPI-style).

``create_task``    — takes a request model, no auth (VULNERABLE)
``get_task``       — path param task_id, no auth (VULNERABLE)
``get_task_protected`` — has Depends(get_current_user) (SAFE)
``health``         — health check (SAFE)
"""
from fastapi import FastAPI, Depends

app = FastAPI()


def get_current_user():
    return {"id": 1}


@app.post("/task")
def create_task(request: dict):
    return {"created": request}


@app.get("/task/{task_id}")
def get_task(task_id: str):
    return {"task": task_id}


@app.get("/task/{task_id}/protected")
def get_task_protected(task_id: str, user: dict = Depends(get_current_user)):
    return {"task": task_id, "user": user["id"]}


@app.get("/health")
def health():
    return {"ok": True}
