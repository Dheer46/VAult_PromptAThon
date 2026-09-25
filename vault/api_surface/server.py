"""API Surface (diagram box): the S3-compatible HTTP server.

Arrow #1: Administrator -> API Surface "administers" (/vault/admin/v1/*, vaultctl).
Arrow #2: Storage Client -> API Surface "sends requests" (S3 HTTP, SigV4 signed).
Arrow #3: API Surface -> Application Facade "enters application" (router handlers).

Middleware: assigns x-amz-request-id, authenticates (SigV4 / presigned / Keystone
token), times the request and counts bytes, records Prometheus metrics, and after
the response sends an entry to the Audit Pipeline — failed requests included.
"""
from __future__ import annotations

import time
import uuid

from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .. import errors
from ..app_facade.context import RequestContext
from ..observability import metrics
from ..observability.log import log
from ..ops.scanner import ActivityGauge
from ..security.iam import ANONYMOUS
from . import s3_xml as X
from . import sigv4
from .router import S3Request, S3Router


async def _raw_stream(request: Request):
    async for chunk in request.stream():
        if chunk:
            yield chunk


async def _drain(request: Request, resp: Response, limit: int = 8 * 1024 * 1024) -> None:
    """An early error leaves the body unread; consume it (or close the connection)
    so the next request on this keep-alive connection isn't parsed from body bytes."""
    try:
        n = 0
        async for chunk in request.stream():
            n += len(chunk)
            if n > limit:
                resp.headers["connection"] = "close"
                return
    except Exception:
        pass


def error_response(e: errors.S3Error, ctx: RequestContext, head: bool = False) -> Response:
    headers = {"x-amz-request-id": ctx.request_id, **(e.extra.get("headers") or {})}
    if e.status == 304 or head:
        return Response(status_code=e.status, headers=headers)
    extra = {k: v for k, v in e.extra.items() if isinstance(v, str) and k[0].isupper()}
    body = X.error_xml(e.code, e.message, f"/{ctx.bucket}/{ctx.key}".rstrip("/"), ctx.request_id,
                       ctx.bucket, ctx.key, **extra)
    return Response(body, status_code=e.status, media_type="application/xml", headers=headers)


class Authenticator:
    def __init__(self, iam, keystone=None):
        self.iam = iam
        self.keystone = keystone

    async def authenticate(self, request: Request, headers: dict, raw_path: str, raw_query: str):
        token = headers.get("x-auth-token")
        if token and self.keystone and self.keystone.enabled:
            return await self.keystone.validate(token), None  # arrow #17
        if "authorization" in headers or "X-Amz-Signature=" in raw_query:
            try:
                res = sigv4.verify(request.method, raw_path, raw_query, headers, self.iam.lookup)
                return res.identity, res
            except errors.S3Error as e:
                if e.code == "InvalidAccessKeyId" and self.keystone and self.keystone.enabled \
                        and "authorization" in headers:
                    p = sigv4.parse_authorization(headers["authorization"])
                    ident = await self.keystone.ec2_validate(
                        p["access_key"], p["signature"], headers.get("host", ""), request.method,
                        raw_path, {k: v for k, v in headers.items() if k in p["signed_headers"]},
                        headers.get("x-amz-content-sha256", ""))
                    if ident:
                        return ident, None
                raise
        if "AWSAccessKeyId=" in raw_query and "Signature=" in raw_query:
            raise errors.S3Error("AccessDenied", "Signature Version 2 is not supported; use SigV4")
        return ANONYMOUS, None


def create_app(node) -> Starlette:
    """node: the assembled VaultNode (see vault.main)."""
    router = S3Router(node.app_facade, node.oidc, node.settings)
    auth = Authenticator(node.iam, node.keystone)

    async def s3_entry(request: Request) -> Response:
        rid = uuid.uuid4().hex[:16].upper()
        client = request.client.host if request.client else ""
        ctx = RequestContext(request_id=rid, source_ip=request.headers.get("x-forwarded-for", client)
                             .split(",")[0].strip(), secure=request.url.scheme == "https")
        t0 = time.perf_counter()
        ActivityGauge.in_flight += 1
        headers = {k.lower(): v for k, v in request.headers.items()}
        status = 500
        resp_headers: dict = {}
        err_code = ""
        try:
            raw_path = request.scope.get("raw_path", b"/").decode("latin-1").split("?")[0]
            raw_query = request.scope.get("query_string", b"").decode("latin-1")
            ident, authres = await auth.authenticate(request, headers, raw_path, raw_query)
            ctx.identity = ident
            sha = headers.get("x-amz-content-sha256", "")
            body = _raw_stream(request)
            size = int(headers["content-length"]) if headers.get("content-length", "").isdigit() else -1
            if sha.startswith("STREAMING-") or "aws-chunked" in headers.get("content-encoding", ""):
                body = sigv4.decode_aws_chunked(body, authres, signed=sha in (
                    sigv4.STREAMING_SIGNED, sigv4.STREAMING_SIGNED_TRAILER))
                size = int(headers.get("x-amz-decoded-content-length", -1))
            resp = await router.dispatch(S3Request(request, ctx, body, size))
            status = resp.status_code
        except errors.S3Error as e:
            err_code = e.code
            if e.status >= 500:
                log.warning("s3 error", code=e.code, msg=e.message, api=ctx.api, request_id=rid)
            resp = error_response(e, ctx, head=request.method == "HEAD")
            status = e.status
        except errors.LockLost as e:
            err_code = "SlowDown"
            resp = error_response(errors.S3Error("SlowDown", f"lock lost: {e}", 503), ctx)
            status = 503
        except Exception as e:
            err_code = "InternalError"
            log.exception("internal error", api=ctx.api, request_id=rid, error=str(e))
            resp = error_response(errors.S3Error("InternalError", "We encountered an internal error.", 500), ctx,
                                  head=request.method == "HEAD")
            status = 500
        finally:
            ActivityGauge.in_flight -= 1
        if status >= 300 and request.method in ("PUT", "POST"):
            await _drain(request, resp)
        resp.headers["x-amz-request-id"] = rid
        resp.headers["server"] = "Vault"
        resp_headers = dict(resp.headers)
        api = ctx.api or "Unknown"
        elapsed = time.perf_counter() - t0
        metrics.S3_REQUESTS.labels(api, str(status)).inc()
        metrics.S3_DURATION.labels(api).observe(elapsed)
        if ctx.bytes_in:
            metrics.S3_BYTES_RX.labels(api).inc(ctx.bytes_in)
        if ctx.bytes_out:
            metrics.S3_BYTES_TX.labels(api).inc(ctx.bytes_out)
        if node.audit and node.audit.enabled:  # every request, success or failure
            node.audit.log(node.audit.entry(ctx, status, dict(request.headers), resp_headers,
                                            elapsed * 1000, err_code))
        return resp

    async def health(request: Request) -> Response:
        kind = request.path_params["kind"]
        if kind == "live":
            return JSONResponse({"status": "ok"})
        if kind == "ready":
            ok = node.ready
            return JSONResponse({"status": "ok" if ok else "starting"}, status_code=200 if ok else 503)
        if kind == "cluster":
            ok = node.ready and await node.storage.has_write_quorum()
            return JSONResponse({"status": "ok" if ok else "degraded"}, status_code=200 if ok else 503)
        return JSONResponse({"error": "unknown"}, status_code=404)

    async def prom(request: Request) -> Response:
        if node.ready:
            try:
                await node.storage.storage_info()  # refreshes drive gauges
            except Exception:
                pass
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    async def admin(request: Request) -> Response:
        return await node.admin_api.handle(request)

    from ..admin.console import ConsoleAPI
    console = ConsoleAPI(node)
    routes = [
        Route("/vault/console", console.page, methods=["GET"]),  # web console (frontend)
        Route("/vault/console/api/{path:path}", console.handle, methods=["GET", "PUT", "POST", "DELETE"]),
        Route("/vault/admin/v1/{path:path}", admin, methods=["GET", "PUT", "POST", "DELETE"]),  # arrow #1
        Route("/vault/health/{kind}", health, methods=["GET", "HEAD"]),
        Route("/metrics", prom, methods=["GET"]),
        Route("/{path:path}", s3_entry, methods=["GET", "PUT", "POST", "DELETE", "HEAD"]),  # arrow #2
    ]
    return Starlette(routes=routes)
