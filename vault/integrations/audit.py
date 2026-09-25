"""Audit Pipeline (diagram box) — arrow #14: Audit Pipeline -> Audit Targets
"dispatches entries".

The API Surface middleware produces one entry per request (success or failure,
admin API included); secrets are redacted before sending."""
from __future__ import annotations

from datetime import datetime, timezone

REDACT = {"authorization", "x-auth-token", "x-amz-security-token",
          "x-amz-server-side-encryption-customer-key",
          "x-amz-copy-source-server-side-encryption-customer-key", "cookie"}


def redact(headers: dict) -> dict:
    return {k: ("REDACTED" if k.lower() in REDACT else v) for k, v in headers.items()}


class AuditLogger:
    def __init__(self, registry, node: str):
        self.registry = registry
        self.node = node

    @property
    def enabled(self) -> bool:
        return bool(self.registry.audit)

    def entry(self, ctx, status: int, req_headers: dict, resp_headers: dict, duration_ms: float,
              error: str = "") -> dict:
        now = datetime.now(timezone.utc)
        return {
            "version": "1", "time": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "node": self.node, "requestID": ctx.request_id,
            "api": {"name": ctx.api, "bucket": ctx.bucket, "object": ctx.key,
                    "status": "OK" if status < 400 else error or "Error", "statusCode": status,
                    "rx": ctx.bytes_in, "tx": ctx.bytes_out, "timeToResponse": f"{duration_ms:.0f}ms"},
            "remotehost": ctx.source_ip, "userAgent": req_headers.get("user-agent", ""),
            "accessKey": ctx.identity.access_key if ctx.identity else "",
            "identitySource": ctx.identity.source if ctx.identity else "anonymous",
            "requestHeader": redact(req_headers), "responseHeader": redact(resp_headers),
            "tags": ctx.tags,
        }

    def log(self, entry: dict) -> None:
        for t in self.registry.audit.values():
            t.enqueue(entry)
