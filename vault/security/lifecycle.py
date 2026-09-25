"""Lifecycle Engine (diagram box) — arrow #15: Lifecycle Engine -> Remote S3
"tiers objects" (dotted; boto3).

Rules come from PutBucketLifecycleConfiguration XML. The Scanner calls
`evaluate` for every object; expiration beats transition. Transitioned objects
keep their metadata locally (HEAD/LIST stay instant) and GET proxies the bytes
from the remote tier. Deleting a transitioned object journals the remote key; a
worker deletes it in the background.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone

from .. import errors
from ..api_surface.s3_xml import parse
from ..integrations.queue_store import QueueStore
from ..observability import metrics
from ..observability.log import log
from ..ops.replication import object_tags
from ..storage_core.filemeta import TRANSITION_STATUS, TRANSITIONED_OBJECT, FileMeta
from ..storage_core.storage_api import SYS_VOL

TIERS_KEY = "config/tiers.json"


def _int(el, path):
    v = el.findtext(path)
    return int(v) if v not in (None, "") else None


def parse_lifecycle(xml: str) -> list[dict]:
    root = parse(xml.encode() if isinstance(xml, str) else xml)
    rules = []
    for r in root.findall("Rule"):
        f = r.find("Filter")
        flt = {"prefix": r.findtext("Prefix") or "", "tags": {}, "gt": None, "lt": None}
        if f is not None:
            src = f.find("And") if f.find("And") is not None else f
            flt["prefix"] = src.findtext("Prefix") or flt["prefix"]
            for t in src.findall("Tag"):
                flt["tags"][t.findtext("Key") or ""] = t.findtext("Value") or ""
            flt["gt"] = _int(src, "ObjectSizeGreaterThan")
            flt["lt"] = _int(src, "ObjectSizeLessThan")
        exp = r.find("Expiration")
        date = exp.findtext("Date") if exp is not None else None
        rules.append({
            "id": r.findtext("ID") or f"rule-{len(rules) + 1}",
            "status": r.findtext("Status") or "Enabled",
            "filter": flt,
            "expiration_days": _int(exp, "Days") if exp is not None else None,
            "expiration_date": datetime.fromisoformat(date.replace("Z", "+00:00")).timestamp() if date else None,
            "expired_delete_marker": exp is not None and (exp.findtext("ExpiredObjectDeleteMarker") or "") == "true",
            "noncurrent_days": _int(r, "NoncurrentVersionExpiration/NoncurrentDays"),
            "newer_noncurrent": _int(r, "NoncurrentVersionExpiration/NewerNoncurrentVersions"),
            "transition_days": _int(r, "Transition/Days"),
            "transition_date": (datetime.fromisoformat(r.findtext("Transition/Date").replace("Z", "+00:00")).timestamp()
                                if r.findtext("Transition/Date") else None),
            "transition_tier": r.findtext("Transition/StorageClass"),
            "noncurrent_transition_days": _int(r, "NoncurrentVersionTransition/NoncurrentDays"),
            "noncurrent_transition_tier": r.findtext("NoncurrentVersionTransition/StorageClass"),
            "abort_mpu_days": _int(r, "AbortIncompleteMultipartUpload/DaysAfterInitiation"),
        })
    if not rules:
        raise errors.S3Error("MalformedXML", "lifecycle configuration needs at least one Rule")
    return rules


def _matches(rule: dict, key: str, v) -> bool:
    f = rule["filter"]
    if rule["status"] != "Enabled" or not key.startswith(f["prefix"]):
        return False
    tags = object_tags(v.meta_user) if f["tags"] else {}
    if any(tags.get(k) != val for k, val in f["tags"].items()):
        return False
    if f["gt"] is not None and v.size <= f["gt"]:
        return False
    if f["lt"] is not None and v.size >= f["lt"]:
        return False
    return True


class TierManager:
    """Remote S3 tiers configured via PUT /vault/admin/v1/tiers/{NAME}."""

    def __init__(self, storage):
        self.storage = storage
        self.tiers: dict[str, dict] = {}
        self._clients: dict[str, object] = {}

    async def load(self) -> None:
        try:
            self.tiers = json.loads(await self.storage.get_object_bytes(SYS_VOL, TIERS_KEY))
        except errors.S3Error:
            self.tiers = {}
        self._clients.clear()

    async def put(self, name: str, cfg: dict) -> None:
        if cfg.get("type", "s3") != "s3" or not cfg.get("bucket"):
            raise errors.S3Error("InvalidArgument", "tier needs type=s3 and bucket")
        self.tiers[name.upper()] = cfg
        self._clients.pop(name.upper(), None)
        await self.storage.put_object_bytes(SYS_VOL, TIERS_KEY, json.dumps(self.tiers).encode())

    def client(self, name: str):
        cfg = self.tiers.get(name.upper())
        if cfg is None:
            raise errors.S3Error("InvalidStorageClass", f"tier {name} not configured")
        c = self._clients.get(name.upper())
        if c is None:
            import boto3
            from botocore.config import Config
            c = boto3.client("s3", endpoint_url=cfg.get("endpoint") or None,
                             aws_access_key_id=cfg.get("access_key"),
                             aws_secret_access_key=cfg.get("secret_key"),
                             region_name=cfg.get("region") or "us-east-1",
                             config=Config(s3={"addressing_style": "path"}, connect_timeout=5,
                                           request_checksum_calculation="when_required",
                                           response_checksum_validation="when_required"))
            self._clients[name.upper()] = c
        return c, cfg

    async def read(self, info: dict, offset: int, length: int):
        """Stream bytes of a transitioned object from its tier (GET proxies through Vault)."""
        client, cfg = self.client(info["tier"])
        rng = f"bytes={offset}-{offset + length - 1}" if length > 0 else None
        kw = {"Bucket": cfg["bucket"], "Key": info["remote_key"]}
        if rng:
            kw["Range"] = rng
        if length == 0:
            return
        resp = await asyncio.to_thread(client.get_object, **kw)
        body = resp["Body"]
        while True:
            chunk = await asyncio.to_thread(body.read, 1 << 20)
            if not chunk:
                break
            yield chunk


class LifecycleEngine:
    def __init__(self, settings, storage, bucket_meta, tiers: TierManager, queue_dir: str,
                 events=None):
        self.s = settings
        self.storage = storage
        self.bucket_meta = bucket_meta
        self.tiers = tiers
        self.events = events
        self.journal = QueueStore(os.path.join(queue_dir, "tier-journal"))

    @property
    def day(self) -> int:
        return self.s.lifecycle_day_seconds

    def rules(self, bm) -> list[dict] | None:
        return bm.parsed("lifecycle", "lifecycle_xml", parse_lifecycle)

    def evaluate(self, bm, key: str, fm: FileMeta, now: float | None = None) -> list[tuple]:
        """Returns actions: ("expire"|"transition"|"expire_version"|"transition_version"|
        "expire_delete_marker", version_id, tier)."""
        rules = self.rules(bm)
        if not rules or not fm.versions:
            return []
        now = now or time.time()
        actions: list[tuple] = []
        versions = fm.versions
        latest = versions[0]
        # current version
        if latest.is_delete_marker:
            if len(versions) == 1 and any(r["expired_delete_marker"] and _matches(r, key, latest)
                                          for r in rules):
                actions.append(("expire_delete_marker", latest.version_id, None))
        else:
            age = now - latest.mod_time_ns / 1e9
            for r in rules:
                if not _matches(r, key, latest):
                    continue
                if (r["expiration_days"] is not None and age >= r["expiration_days"] * self.day) or \
                        (r["expiration_date"] and now >= r["expiration_date"]):
                    actions = [("expire", latest.version_id, None)]
                    break  # expiration beats transition
                due = (r["transition_days"] is not None and age >= r["transition_days"] * self.day) or \
                    (r["transition_date"] and now >= r["transition_date"])
                if due and r["transition_tier"] and TRANSITIONED_OBJECT not in latest.meta_sys:
                    actions.append(("transition", latest.version_id, r["transition_tier"]))
        # noncurrent versions use the time the version became noncurrent
        noncurrent = versions[1:]
        for i, v in enumerate(noncurrent):
            became = versions[i].mod_time_ns / 1e9  # the next newer version's time
            nc_age = now - became
            for r in rules:
                if not _matches(r, key, v):
                    continue
                keep = r["newer_noncurrent"]
                if r["noncurrent_days"] is not None and nc_age >= r["noncurrent_days"] * self.day \
                        and (keep is None or i >= keep):
                    actions.append(("expire_version", v.version_id, None))
                    break
                if r["noncurrent_transition_days"] is not None and not v.is_delete_marker \
                        and nc_age >= r["noncurrent_transition_days"] * self.day \
                        and TRANSITIONED_OBJECT not in v.meta_sys and r["noncurrent_transition_tier"]:
                    actions.append(("transition_version", v.version_id, r["noncurrent_transition_tier"]))
                    break
        return actions

    async def apply(self, bm, key: str, actions: list[tuple]) -> None:
        for action, vid, tier in actions:
            try:
                if action == "expire":
                    res = await self.storage.delete_object(bm.name, key, None, bm.versioning)
                    await self._journal_deleted(res)
                    if self.events:
                        await self.events.send("s3:LifecycleExpiration:Delete" if not res["delete_marker"]
                                               else "s3:LifecycleExpiration:DeleteMarkerCreated",
                                               bm.name, key, version_id=res.get("version_id") or "")
                elif action in ("expire_version", "expire_delete_marker"):
                    res = await self.storage.delete_object(bm.name, key, vid, bm.versioning)
                    await self._journal_deleted(res)
                    if self.events:
                        await self.events.send("s3:LifecycleExpiration:Delete", bm.name, key, version_id=vid)
                elif action in ("transition", "transition_version"):
                    await self.transition(bm.name, key, vid, tier)
                    if self.events:
                        await self.events.send("s3:ObjectTransition:Complete", bm.name, key, version_id=vid)
                metrics.LIFECYCLE_ACTIONS.labels(action).inc()
                log.info("lifecycle action", action=action, bucket=bm.name, key=key, version_id=vid)
            except Exception as e:
                log.warning("lifecycle action failed", action=action, bucket=bm.name, key=key, error=str(e))
                if self.events and action.startswith("transition"):
                    await self.events.send("s3:ObjectTransition:Failed", bm.name, key, version_id=vid)

    async def transition(self, bucket: str, key: str, version_id: str, tier: str) -> None:
        """Arrow #15 "tiers objects": lock, stream (still encrypted) to the tier under a
        random key, flip metadata, drop local data, unlock."""
        client, cfg = self.tiers.client(tier)
        s = await self.storage.pools.set_for_existing(bucket, key)
        lk = await s.ns.write(f"{bucket}/{key}") if s.ns else None
        try:
            fv, metas, mask = await s.get_object_info(bucket, key, version_id)
            if TRANSITIONED_OBJECT in fv.meta_sys or fv.is_delete_marker:
                return
            remote_key = f"{cfg.get('prefix', '')}{uuid.uuid4()}"
            with tempfile.SpooledTemporaryFile(max_size=16 * 1024 * 1024) as f:
                async for chunk in s.read_object(bucket, key, fv, metas, mask):
                    f.write(chunk)
                f.seek(0)
                await asyncio.to_thread(client.upload_fileobj, f, cfg["bucket"], remote_key)
            head = await asyncio.to_thread(client.head_object, Bucket=cfg["bucket"], Key=remote_key)
            info = {"tier": tier.upper(), "remote_key": remote_key,
                    "remote_version": head.get("VersionId", "") or ""}
            await s.update_version_meta(bucket, key, fv.version_id,
                                        meta_sys={TRANSITION_STATUS: "complete",
                                                  TRANSITIONED_OBJECT: info},
                                        drop_data=True, storage_class=tier.upper(), lock=False)
        finally:
            if lk:
                await lk.release()

    async def _journal_deleted(self, res: dict) -> None:
        v = res.get("deleted")
        if v is not None and TRANSITIONED_OBJECT in v.meta_sys:
            self.journal.put(v.meta_sys[TRANSITIONED_OBJECT])

    def journal_delete(self, v) -> None:
        if v is not None and TRANSITIONED_OBJECT in v.meta_sys:
            self.journal.put(v.meta_sys[TRANSITIONED_OBJECT])

    async def journal_worker(self) -> None:
        """Deletes remote tier objects whose local metadata is gone."""
        while True:
            for name in self.journal.list(100):
                info = self.journal.get(name)
                if not info:
                    self.journal.delete(name)
                    continue
                try:
                    client, cfg = self.tiers.client(info["tier"])
                    await asyncio.to_thread(client.delete_object, Bucket=cfg["bucket"], Key=info["remote_key"])
                    self.journal.delete(name)
                except Exception as e:
                    log.debug("tier journal delete failed", error=str(e))
            await asyncio.sleep(10)

    async def abort_stale_uploads(self, bm) -> int:
        rules = self.rules(bm) or []
        days = [r["abort_mpu_days"] for r in rules if r["abort_mpu_days"] is not None and r["status"] == "Enabled"]
        aborted = 0
        horizon = time.time() - (min(days) * self.day if days else self.s.multipart_expiry_hours * 3600)
        for up in await self.storage.list_multipart_uploads(bm.name):
            if up.mod_time_ns / 1e9 < horizon:
                try:
                    await self.storage.abort_multipart_upload(bm.name, up.meta_sys["key"], up.version_id)
                    aborted += 1
                except Exception:
                    pass
        return aborted


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
