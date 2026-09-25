"""Admin API — arrow #1: Administrator -> API Surface "administers".

Routes under /vault/admin/v1/, signed with SigV4 like S3 requests, and requiring
the consoleAdmin policy (action admin:*). Every admin call is audited.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid

from starlette.requests import Request
from starlette.responses import JSONResponse

from .. import errors
from ..api_surface import sigv4
from ..app_facade.context import RequestContext


def _ok(data=None, status: int = 200) -> JSONResponse:
    return JSONResponse(data if data is not None else {"ok": True}, status_code=status)


class AdminAPI:
    def __init__(self, node):
        self.n = node

    async def _auth(self, request: Request, ctx: RequestContext, action: str, body: bytes) -> None:
        headers = {k.lower(): v for k, v in request.headers.items()}
        headers.setdefault("x-amz-content-sha256", hashlib.sha256(body).hexdigest())
        raw_path = request.scope.get("raw_path", b"/").decode("latin-1").split("?")[0]
        raw_query = request.scope.get("query_string", b"").decode("latin-1")
        res = sigv4.verify(request.method, raw_path, raw_query, headers, self.n.iam.lookup)
        ctx.identity = res.identity
        if not self.n.iam.authorize(res.identity, f"admin:{action}"):
            raise errors.S3Error("AccessDenied", "admin API requires the consoleAdmin policy")

    async def handle(self, request: Request) -> JSONResponse:
        path = request.path_params["path"].strip("/")
        parts = path.split("/") if path else []
        m = request.method
        ctx = RequestContext(request_id=uuid.uuid4().hex[:16].upper(),
                             source_ip=request.client.host if request.client else "", api=f"Admin:{m}:{path}")
        t0 = time.time()
        status, err = 200, ""
        try:
            body = await request.body()
            await self._auth(request, ctx, parts[0] if parts else "Info", body)
            data = json.loads(body) if body else {}
            resp = await self._route(m, parts, data, request)
            status = resp.status_code
            return resp
        except errors.S3Error as e:
            status, err = e.status, e.code
            return JSONResponse({"error": e.code, "message": e.message}, status_code=e.status)
        except (KeyError, ValueError, json.JSONDecodeError) as e:
            status, err = 400, "InvalidArgument"
            return JSONResponse({"error": "InvalidArgument", "message": str(e)}, status_code=400)
        finally:
            if self.n.audit and self.n.audit.enabled:
                self.n.audit.log(self.n.audit.entry(ctx, status, dict(request.headers), {},
                                                    (time.time() - t0) * 1000, err))

    async def _route(self, m: str, p: list[str], d: dict, request: Request) -> JSONResponse:
        n = self.n
        head = p[0] if p else "info"
        q = dict(request.query_params)
        if head == "info" and m == "GET":
            local = await n.server_info()
            peers = await n.peers.server_infos() if n.peers else []
            return _ok({"nodes": [local] + peers, "storage": await n.storage.storage_info()})
        # --- users / policies / groups (IAM)
        if head == "users":
            if m == "GET" and len(p) == 1:
                return _ok(n.iam.list_users())
            if m == "PUT" and len(p) == 2:
                return _ok(await n.iam.create_user(p[1], d["secret_key"], d.get("policies", [])))
            if m == "DELETE" and len(p) == 2:
                await n.iam.delete_user(p[1])
                return _ok()
            if m == "POST" and len(p) == 3 and p[2] == "status":
                await n.iam.set_user_status(p[1], d["status"])
                return _ok()
        if head == "policies":
            if m == "GET":
                return _ok(sorted(n.iam.policies))
            if m == "PUT" and len(p) == 2:
                await n.iam.put_policy(p[1], d)
                return _ok()
            if m == "DELETE" and len(p) == 2:
                await n.iam.delete_policy(p[1])
                return _ok()
        if head == "attach" and m == "POST":
            await n.iam.attach_policy(d["policy"], user=d.get("user"), group=d.get("group"))
            return _ok()
        if head == "groups" and m == "POST" and len(p) == 3 and p[2] == "members":
            await n.iam.add_to_group(p[1], d["user"])
            return _ok()
        # --- healing
        if head == "heal":
            if m == "GET" and len(p) == 2 and p[1] == "status":
                return _ok(n.healing.info())
            if m == "POST" and len(p) >= 2:
                res = await n.healing.heal_prefix(p[1], "/".join(p[2:]), deep=q.get("deep") == "true")
                return _ok(res)
        # --- replication
        if head == "replication":
            if m == "GET" and p[1:] == ["metrics"]:
                return _ok(await n.replication_metrics.snapshot())
            if m == "PUT" and len(p) == 3 and p[1] == "targets":
                bucket = p[2]
                for f in ("endpoint", "bucket", "access_key", "secret_key"):
                    if f not in d:
                        raise errors.S3Error("InvalidArgument", f"missing {f}")
                bm = await n.bucket_meta.get(bucket)
                arn = d.get("arn") or f"arn:vault:replication::{uuid.uuid4().hex[:8]}:{d['bucket']}"
                targets = dict(bm.replication_targets or {})
                targets[arn] = {k: d[k] for k in ("endpoint", "bucket", "access_key", "secret_key")}
                targets[arn]["region"] = d.get("region", "us-east-1")
                await n.bucket_meta.update(bucket, "replication_targets", targets)
                return _ok({"arn": arn})
            if m == "GET" and len(p) == 3 and p[1] == "targets":
                bm = await n.bucket_meta.get(p[2])
                return _ok({a: {k: v for k, v in t.items() if k != "secret_key"}
                            for a, t in (bm.replication_targets or {}).items()})
        # --- lifecycle tiers
        if head == "tiers":
            if m == "GET":
                return _ok({k: {kk: vv for kk, vv in v.items() if kk != "secret_key"}
                            for k, v in n.tiers.tiers.items()})
            if m == "PUT" and len(p) == 2:
                await n.tiers.put(p[1], d)
                if n.peers:
                    await n.peers.notify_all("reload-tiers")
                return _ok()
        # --- event / audit targets
        if head == "targets":
            if m == "GET":
                return _ok(n.targets.info())
            if m == "PUT" and len(p) == 3:
                role = d.pop("role", "events")
                arn = await n.targets.define(role, {"type": p[1], "name": p[2], **d})
                return _ok({"arn": arn})
        # --- KMS
        if head == "kms":
            if m == "GET" and p[1:] == ["status"]:
                return _ok(await n.kms.status())
            if m == "POST" and len(p) == 3 and p[1] == "keys":
                await n.kms.create_key(p[2])  # forwarded to the KMS Provider
                return _ok({"key": p[2]})
        if head == "scanner" and m == "GET":
            return _ok(n.scanner.info() if n.scanner else {})
        if head == "usage" and m == "GET":
            return _ok(await n.usage())
        if head == "locks" and m == "GET":
            return _ok(n.lock_table.snapshot())
        if head == "buckets" and m == "GET" and len(p) == 2:
            bm = await n.bucket_meta.get(p[1])
            return _ok({"name": bm.name, "versioning": bm.versioning, "created": bm.created,
                        "has_policy": bool(bm.policy), "has_lifecycle": bool(bm.lifecycle_xml),
                        "has_replication": bool(bm.replication_xml),
                        "has_notification": bool(bm.notification_xml),
                        "encryption": bool(bm.encryption_xml),
                        "replication_targets": list((bm.replication_targets or {}).keys())})
        raise errors.S3Error("InvalidArgument", f"unknown admin route {m} /{'/'.join(p)}", 404)
