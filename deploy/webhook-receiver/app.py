"""Tiny webhook receiver for Event Targets and Audit Targets: logs every JSON body
and appends it to /data/<path>.jsonl. GET /<path> returns what was received."""
import json
import os

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

DATA = os.environ.get("DATA_DIR", "/data")
os.makedirs(DATA, exist_ok=True)


async def receive(request: Request):
    name = request.path_params["name"]
    path = os.path.join(DATA, f"{name}.jsonl")
    if request.method == "POST":
        body = await request.json()
        with open(path, "a") as f:
            f.write(json.dumps(body) + "\n")
        summary = body.get("EventName") or body.get("api", {}).get("name")
        print(f"[{name}] {summary} {body.get('Key') or body.get('api', {}).get('object', '')}", flush=True)
        return JSONResponse({"ok": True})
    if request.method == "HEAD":
        return JSONResponse({})
    try:
        with open(path) as f:
            lines = [json.loads(line) for line in f]
    except FileNotFoundError:
        lines = []
    limit = int(request.query_params.get("limit", 100))
    return JSONResponse({"count": len(lines), "items": lines[-limit:]})


app = Starlette(routes=[Route("/{name}", receive, methods=["GET", "POST", "HEAD"])])
