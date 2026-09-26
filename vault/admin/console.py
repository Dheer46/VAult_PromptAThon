"""Web console API (served at /vault/console). Login with an access key + secret; the
session is an HMAC-signed cookie, and every call runs through the Application Facade
with that identity, so IAM policies apply exactly as for S3 requests."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import uuid

from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response, StreamingResponse

from .. import errors
from ..app_facade.context import RequestContext

COOKIE = "vault_session"
TTL = 12 * 3600
STATIC = os.path.join(os.path.dirname(__file__), "console.html")


class ConsoleAPI:
    def __init__(self, node):
        self.n = node
        self._key = hashlib.sha256(f"console|{node.settings.root_password}".encode()).digest()

    # ------------------------------------------------------------- session
    def _sign(self, ak: str) -> str:
        payload = base64.urlsafe_b64encode(json.dumps({"ak": ak, "exp": time.time() + TTL}).encode()).decode()
        mac = hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}.{mac}"

    def _identity(self, request: Request):
        raw = request.cookies.get(COOKIE, "")
        payload, _, mac = raw.partition(".")
        if not payload or not hmac.compare_digest(
                mac, hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()):
            raise errors.S3Error("AccessDenied", "not logged in", 401)
        d = json.loads(base64.urlsafe_b64decode(payload))
        if d["exp"] < time.time():
            raise errors.S3Error("AccessDenied", "session expired", 401)
        found = self.n.iam.lookup(d["ak"])
        if not found:
            raise errors.S3Error("AccessDenied", "user no longer exists", 401)
        return found[1]

    def _ctx(self, request: Request, ident) -> RequestContext:
        return RequestContext(request_id=uuid.uuid4().hex[:16].upper(), identity=ident,
                              source_ip=request.client.host if request.client else "", api="Console")

    def _is_admin(self, ident) -> bool:
        return self.n.iam.authorize(ident, "admin:Info")

    # -------------------------------------------------------------- routes
    async def page(self, request: Request) -> Response:
        return FileResponse(STATIC, media_type="text/html")

    async def handle(self, request: Request) -> Response:
        path = request.path_params["path"].strip("/")
        m = request.method
        try:
            if path == "login" and m == "POST":
                d = await request.json()
                found = self.n.iam.lookup(d.get("access_key", ""))
                if not found or not hmac.compare_digest(found[0], d.get("secret_key", "")):
                    raise errors.S3Error("AccessDenied", "invalid access key or secret", 401)
                r = JSONResponse({"user": found[1].user, "admin": self._is_admin(found[1])})
                r.set_cookie(COOKIE, self._sign(d["access_key"]), max_age=TTL, httponly=True, samesite="strict")
                return r
            if path == "logout":
                r = JSONResponse({"ok": True})
                r.delete_cookie(COOKIE)
                return r
            ident = self._identity(request)
            ctx = self._ctx(request, ident)
            return await self._route(request, m, path, ident, ctx)
        except errors.S3Error as e:
            return JSONResponse({"error": e.code, "message": e.message}, status_code=e.status)

    async def _route(self, request, m, path, ident, ctx) -> Response:
        app, n, q = self.n.app_facade, self.n, request.query_params
        if path == "me":
            return JSONResponse({"user": ident.user, "source": ident.source, "admin": self._is_admin(ident),
                                 "policies": ident.policies})
        if path == "buckets" and m == "GET":
            out = []
            for b in await app.list_buckets(ctx):
                bm = await n.bucket_meta.get(b["name"])
                out.append({"name": b["name"], "created": b["created"] / 1e9, "versioning": bm.versioning,
                            "encrypted": bool(bm.encryption_xml), "replication": bool(bm.replication_xml),
                            "lifecycle": bool(bm.lifecycle_xml), "events": bool(bm.notification_xml),
                            "public": bool(bm.policy)})
            return JSONResponse(out)
        if path == "buckets" and m == "POST":
            d = await request.json()
            await app.create_bucket(ctx, d["name"])
            if d.get("versioning"):
                await app.put_bucket_config(ctx, d["name"], "PutBucketVersioning", "versioning", "Enabled")
            return JSONResponse({"ok": True})
        if path == "buckets" and m == "DELETE":
            await app.delete_bucket(ctx, q["name"])
            return JSONResponse({"ok": True})
        if path == "objects" and m == "GET":
            res = await app.list_objects(ctx, q["bucket"], q.get("prefix", ""), "/", q.get("marker", ""), 500)
            return JSONResponse({
                "prefixes": res.prefixes,
                "objects": [{"key": o.key, "size": app.objects.plain_size(o.version),
                             "modified": o.version.mod_time_ns / 1e9, "etag": o.version.etag,
                             "version": o.version.version_id,
                             "encrypted": "x-vault-internal-sse" in o.version.meta_sys,
                             "storage_class": o.version.meta_user.get("x-amz-storage-class", "STANDARD"),
                             "replication": o.version.meta_sys.get("x-vault-replication-status", "")}
                            for o in res.objects],
                "truncated": res.is_truncated, "next": res.next_marker})
        if path == "objects" and m == "PUT":
            size = int(request.headers.get("content-length", -1))
            headers = {"content-type": request.headers.get("x-content-type") or "application/octet-stream"}
            if request.headers.get("x-encrypt") == "1":
                headers["x-amz-server-side-encryption"] = "AES256"

            async def body():
                async for c in request.stream():
                    if c:
                        yield c
            h = await app.put_object(ctx, q["bucket"], q["key"], body(), size, headers)
            return JSONResponse({"etag": h.get("etag", "").strip('"')})
        if path == "objects" and m == "DELETE":
            await app.delete_object(ctx, q["bucket"], q["key"], None)
            return JSONResponse({"ok": True})
        if path == "overview" and m == "GET":
            # dashboard feed: per-bucket totals + most recently modified objects
            buckets, recent = [], []
            for b in await app.list_buckets(ctx):
                try:
                    res = await app.list_objects(ctx, b["name"], "", "", "", 1000)
                except errors.S3Error:
                    continue
                total = 0
                for o in res.objects:
                    size = app.objects.plain_size(o.version)
                    total += size
                    recent.append({"bucket": b["name"], "key": o.key, "size": size,
                                   "modified": o.version.mod_time_ns / 1e9,
                                   "encrypted": "x-vault-internal-sse" in o.version.meta_sys,
                                   "replication": o.version.meta_sys.get("x-vault-replication-status", ""),
                                   "storage_class": o.version.meta_user.get("x-amz-storage-class", "STANDARD")})
                buckets.append({"name": b["name"], "objects": len(res.objects), "bytes": total,
                                "truncated": res.is_truncated})
            recent.sort(key=lambda r: r["modified"], reverse=True)
            return JSONResponse({"buckets": buckets, "recent": recent[:12]})
        if path == "download":
            status, h, stream = await app.get_object(ctx, q["bucket"], q["key"], q.get("version") or None, {})
            name = urllib.parse.quote(q["key"].rsplit("/", 1)[-1])
            h["content-disposition"] = f"attachment; filename*=UTF-8''{name}"
            return StreamingResponse(stream, headers=h, media_type=h.get("content-type"))
        # ---------------- admin views
        if not self._is_admin(ident):
            raise errors.S3Error("AccessDenied", "this view needs the consoleAdmin policy", 403)
        if path == "cluster":
            local = await n.server_info()
            peers = await n.peers.server_infos() if n.peers else []
            return JSONResponse({"nodes": [local] + peers, "storage": await n.storage.storage_info()})
        if path == "healing":
            return JSONResponse(n.healing.info())
        if path == "heal" and m == "POST":
            return JSONResponse(await n.healing.heal_prefix(q["bucket"], q.get("prefix", "")))
        if path == "replication":
            return JSONResponse(await n.replication_metrics.snapshot())
        if path == "usage":
            return JSONResponse(await n.usage())
        if path == "services":
            kms = await n.kms.status()
            ks = await n.keystone.healthy() if n.keystone else None
            return JSONResponse({"kms": kms, "keystone": {"configured": bool(n.keystone), "online": ks},
                                 "targets": n.targets.info(), "tiers": list(n.tiers.tiers)})
        if path == "users" and m == "GET":
            return JSONResponse({"users": n.iam.list_users(), "policies": sorted(n.iam.policies)})
        if path == "users" and m == "POST":
            d = await request.json()
            return JSONResponse(await n.iam.create_user(d["access_key"], d["secret_key"], d.get("policies", [])))
        if path == "users" and m == "DELETE":
            await n.iam.delete_user(q["access_key"])
            return JSONResponse({"ok": True})
        raise errors.S3Error("InvalidArgument", f"unknown console route {m} {path}", 404)
