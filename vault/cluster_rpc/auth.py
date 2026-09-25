"""Node-to-node authentication: every RPC carries
`authorization: Bearer <node>:<unix-ts>:<hmac-sha256(secret, node:ts)>`; tokens
older than 15 minutes are rejected."""
from __future__ import annotations

import hashlib
import hmac
import time

import grpc

MAX_AGE = 15 * 60


def make_token(node: str, secret: str, now: float | None = None) -> str:
    ts = str(int(now or time.time()))
    mac = hmac.new(secret.encode(), f"{node}:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"{node}:{ts}:{mac}"


def check_token(token: str, secret: str) -> bool:
    try:
        node, ts, mac = token.rsplit(":", 2)
        age = abs(time.time() - int(ts))
    except ValueError:
        return False
    if age > MAX_AGE:
        return False
    good = hmac.new(secret.encode(), f"{node}:{ts}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(good, mac)


class AuthInterceptor(grpc.aio.ServerInterceptor):
    def __init__(self, secret: str):
        self.secret = secret

    async def intercept_service(self, continuation, handler_call_details):
        md = dict(handler_call_details.invocation_metadata or ())
        auth = md.get("authorization", "")
        if auth.startswith("Bearer ") and check_token(auth[7:], self.secret):
            return await continuation(handler_call_details)
        handler = await continuation(handler_call_details)

        async def abort_uu(request, context):
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "bad cluster token")

        async def abort_stream(request_or_iter, context):
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "bad cluster token")
            yield  # pragma: no cover

        if handler is None:
            return None
        if handler.request_streaming and not handler.response_streaming:
            return grpc.stream_unary_rpc_method_handler(abort_uu)
        if handler.response_streaming:
            return grpc.unary_stream_rpc_method_handler(abort_stream)
        return grpc.unary_unary_rpc_method_handler(abort_uu)
