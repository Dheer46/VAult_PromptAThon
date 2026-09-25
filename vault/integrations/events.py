"""Event Notifications (diagram box) — arrow #13: Event Notifications -> Event Targets
"publishes events".

Bucket rules come from PutBucketNotificationConfiguration XML. Records follow the
AWS S3 event format so existing tools understand them. A slow target never
blocks or fails the S3 request: we enqueue and return."""
from __future__ import annotations

import time
import urllib.parse
from datetime import datetime, timezone
from fnmatch import fnmatchcase

from defusedxml import ElementTree as DET

from .. import errors
from ..api_surface.s3_xml import strip_ns
from ..observability.log import log

_CONFIG_TAGS = {"QueueConfiguration": "Queue", "TopicConfiguration": "Topic",
                "CloudFunctionConfiguration": "CloudFunction"}


def parse_notification(xml: str) -> list[dict]:
    try:
        root = strip_ns(DET.fromstring(xml))
    except Exception:
        raise errors.S3Error("MalformedXML", "notification configuration")
    rules = []
    for tag, arn_tag in _CONFIG_TAGS.items():
        for cfg in root.findall(tag):
            rule = {"id": cfg.findtext("Id") or f"rule-{len(rules) + 1}",
                    "arn": cfg.findtext(arn_tag) or "",
                    "events": [e.text for e in cfg.findall("Event")], "prefix": "", "suffix": ""}
            for fr in cfg.findall("Filter/S3Key/FilterRule"):
                name = (fr.findtext("Name") or "").lower()
                if name in ("prefix", "suffix"):
                    rule[name] = fr.findtext("Value") or ""
            rules.append(rule)
    return rules


def _iso(ns: int | None = None) -> str:
    dt = datetime.fromtimestamp((ns or time.time_ns()) / 1e9, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class EventNotifier:
    def __init__(self, settings, bucket_meta, registry, endpoint: str = ""):
        self.s = settings
        self.bucket_meta = bucket_meta
        self.registry = registry
        self.endpoint = endpoint

    def validate(self, xml: str) -> list[dict]:
        rules = parse_notification(xml)
        for r in rules:
            if r["arn"] not in self.registry.events:
                raise errors.S3Error("InvalidArgument", f"unknown target ARN {r['arn']}",
                                     arn=r["arn"])
        return rules

    def record(self, event_name: str, bucket: str, key: str, size: int, etag: str,
               version_id: str, ctx, config_id: str) -> dict:
        return {"Records": [{
            "eventVersion": "2.0", "eventSource": "vault:s3", "awsRegion": self.s.region,
            "eventTime": _iso(), "eventName": event_name,
            "userIdentity": {"principalId": getattr(ctx, "principal", "") or ""},
            "requestParameters": {"sourceIPAddress": getattr(ctx, "source_ip", "") or ""},
            "responseElements": {"x-amz-request-id": getattr(ctx, "request_id", "") or "",
                                 "x-vault-origin-endpoint": self.endpoint},
            "s3": {"s3SchemaVersion": "1.0", "configurationId": config_id,
                   "bucket": {"name": bucket, "arn": f"arn:aws:s3:::{bucket}",
                              "ownerIdentity": {"principalId": getattr(ctx, "principal", "") or ""}},
                   "object": {"key": urllib.parse.quote(key), "size": size, "eTag": etag,
                              "versionId": "" if version_id == "null" else version_id,
                              "sequencer": f"{time.time_ns():016X}"}}}],
            "EventName": event_name, "Key": f"{bucket}/{key}"}

    async def send(self, event_name: str, bucket: str, key: str, size: int = 0, etag: str = "",
                   version_id: str = "", ctx=None) -> int:
        try:
            bm = await self.bucket_meta.get(bucket)
        except errors.S3Error:
            return 0
        rules = bm.parsed("notification", "notification_xml", parse_notification)
        if not rules:
            return 0
        sent = 0
        for r in rules:
            if not any(fnmatchcase(event_name, p) for p in r["events"]):
                continue
            if not key.startswith(r["prefix"]) or not key.endswith(r["suffix"]):
                continue
            t = self.registry.events.get(r["arn"])
            if t is None:
                log.warning("event target missing", arn=r["arn"], bucket=bucket)
                continue
            t.enqueue(self.record(event_name, bucket, key, size, etag, version_id, ctx, r["id"]))
            sent += 1
        return sent
