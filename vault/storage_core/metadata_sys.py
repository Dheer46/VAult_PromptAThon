"""Bucket Metadata (diagram box). Each bucket's configuration is a msgpack blob
stored as a normal object in the hidden `.vault.sys` bucket, so it is erasure
coded, quorum written and healed like user data. Cached in memory; peers drop
their cache on "reload-bucket-meta"; the whole cache refreshes every 5 minutes.

Arrow #5: Application Facade -> Bucket Metadata "reads config" (`get`).
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Callable

import msgpack

from .. import errors
from ..observability.log import log
from .storage_api import SYS_VOL

REFRESH_INTERVAL = 300


@dataclass
class BucketMetadata:
    name: str
    created: int = 0
    versioning: str = "Unversioned"  # "Enabled" | "Suspended"
    policy: str | None = None  # bucket policy JSON
    lifecycle_xml: str | None = None
    replication_xml: str | None = None
    encryption_xml: str | None = None  # default SSE (SSE-S3 or SSE-KMS + key id)
    notification_xml: str | None = None  # event notification rules
    tagging_xml: str | None = None
    replication_targets: dict = field(default_factory=dict)  # arn -> target config
    quota: int | None = None
    parity: int | None = None  # per-bucket durability policy override
    updated: dict = field(default_factory=dict)  # per field update times

    def __post_init__(self):
        self._parsed: dict[str, tuple[Any, Any]] = {}

    @property
    def versioned(self) -> bool:
        return self.versioning == "Enabled"

    def parsed(self, name: str, source_field: str, parser: Callable[[str], Any]) -> Any:
        """Parsed form of an XML/JSON field, cached so it's not re-parsed per request."""
        src = getattr(self, source_field)
        cached = self._parsed.get(name)
        if cached is not None and cached[0] is src:
            return cached[1]
        value = parser(src) if src else None
        self._parsed[name] = (src, value)
        return value

    def marshal(self) -> bytes:
        return msgpack.packb({f.name: getattr(self, f.name) for f in fields(self)}, use_bin_type=True)

    @staticmethod
    def unmarshal(raw: bytes) -> "BucketMetadata":
        d = msgpack.unpackb(raw, raw=False)
        known = {f.name for f in fields(BucketMetadata)}
        return BucketMetadata(**{k: v for k, v in d.items() if k in known})


def meta_key(bucket: str) -> str:
    return f"buckets/{bucket}/.metadata.bin"


class BucketMetadataSys:
    def __init__(self, storage, peers=None, ns=None):
        self.storage = storage  # StorageFacade
        self.peers = peers
        self.ns = ns
        self.cache: dict[str, BucketMetadata] = {}

    async def _load(self, bucket: str) -> BucketMetadata:
        try:
            raw = await self.storage.get_object_bytes(SYS_VOL, meta_key(bucket))
            return BucketMetadata.unmarshal(raw)
        except errors.S3Error as e:
            if e.code not in ("NoSuchKey", "NoSuchVersion"):
                raise
        if await self.storage.bucket_exists(bucket):
            # bucket dir exists but metadata missing (e.g. created before a crash)
            bm = BucketMetadata(name=bucket, created=time.time_ns())
            return bm
        raise errors.S3Error("NoSuchBucket", bucket)

    async def load_all(self) -> None:
        """On startup."""
        for b in await self.storage.list_buckets():
            try:
                self.cache[b["name"]] = await self._load(b["name"])
            except Exception as e:
                log.warning("bucket metadata load failed", bucket=b["name"], error=str(e))

    async def get(self, bucket: str) -> BucketMetadata:  # arrow #5
        bm = self.cache.get(bucket)
        if bm is None:
            bm = await self._load(bucket)  # raises NoSuchBucket
            self.cache[bucket] = bm
        return bm

    async def save(self, bm: BucketMetadata) -> None:
        await self.storage.put_object_bytes(SYS_VOL, meta_key(bm.name), bm.marshal())
        self.cache[bm.name] = bm
        if self.peers:
            await self.peers.notify_all("reload-bucket-meta", bm.name.encode())

    async def create(self, bucket: str, **kw) -> BucketMetadata:
        bm = BucketMetadata(name=bucket, created=time.time_ns(), **kw)
        await self.save(bm)
        return bm

    async def update(self, bucket: str, field_name: str, value) -> BucketMetadata:
        lk = await self.ns.write(f"{SYS_VOL}/{bucket}/.bucket-meta") if self.ns else None
        try:
            self.cache.pop(bucket, None)
            bm = await self.get(bucket)  # re-read under lock
            setattr(bm, field_name, value)
            bm.updated[field_name] = time.time_ns()
            await self.save(bm)  # other nodes drop their cache
            return bm
        finally:
            if lk:
                await lk.release()

    async def delete(self, bucket: str) -> None:
        self.cache.pop(bucket, None)
        try:
            await self.storage.delete_object(SYS_VOL, meta_key(bucket), evaluate_replication=False)
        except errors.S3Error:
            pass
        if self.peers:
            await self.peers.notify_all("reload-bucket-meta", bucket.encode())

    async def on_reload(self, payload: bytes) -> None:
        self.cache.pop(payload.decode(), None)

    async def refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(REFRESH_INTERVAL)  # safety net for lost notifications
            self.cache.clear()
            try:
                await self.load_all()
            except Exception as e:
                log.warning("bucket metadata refresh failed", error=str(e))

    def all_cached(self) -> list[BucketMetadata]:
        return list(self.cache.values())
