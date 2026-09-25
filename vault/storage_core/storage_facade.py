"""Storage Facade (diagram box): object operations over all pools and sets.

Arrows: receives #4 "delegates storage" (from the Application Facade) and #10
"repairs storage" (from Healing); runs #7 "delegates disk I/O" (through the
erasure sets) and #8 "evaluates replication" after every successful write/delete.
"""
from __future__ import annotations

import asyncio
import base64
from collections import Counter
from dataclasses import dataclass, field
from typing import AsyncIterator

from .. import errors
from ..observability import metrics
from ..observability.log import log
from .erasure_set import ErasureSet, PutOpts
from .filemeta import FileMeta, FileVersion
from .server_pools import ServerPools
from .storage_api import SYS_VOL

MRF_CAPACITY = 100_000


@dataclass
class ObjectInfo:
    bucket: str
    key: str
    version: FileVersion
    set: ErasureSet | None = None
    metas: list = field(default_factory=list)
    mask: list = field(default_factory=list)
    is_latest: bool = True

    @property
    def size(self) -> int:
        return self.version.size


@dataclass
class ListResult:
    objects: list[ObjectInfo] = field(default_factory=list)
    prefixes: list[str] = field(default_factory=list)
    is_truncated: bool = False
    next_marker: str = ""
    next_version_marker: str = ""


class StorageFacade:
    def __init__(self, pools: ServerPools):
        self.pools = pools
        self.replication = None  # set by main: ReplicationSys (arrow #8)
        self.mrf: asyncio.Queue = asyncio.Queue(MRF_CAPACITY)
        self._mrf_pending: set = set()
        for s in pools.all_sets:
            s.on_partial = self.add_partial

    # -------------------------------------------------------------- MRF queue
    def add_partial(self, bucket: str, key: str, version_id: str | None) -> None:
        """A write succeeded with quorum but some drives failed (or a read found
        outdated/corrupt shards): heal it within seconds."""
        item = (bucket, key)
        if item in self._mrf_pending:
            return
        try:
            self.mrf.put_nowait(item)
            self._mrf_pending.add(item)
            metrics.MRF_QUEUE.set(self.mrf.qsize())
        except asyncio.QueueFull:
            pass

    async def mrf_worker(self) -> None:
        while True:
            bucket, key = await self.mrf.get()
            self._mrf_pending.discard((bucket, key))
            metrics.MRF_QUEUE.set(self.mrf.qsize())
            await asyncio.sleep(0.2)  # let the triggering request finish first
            try:
                await self.heal_object(bucket, key, kind="mrf")
            except Exception as e:
                log.debug("mrf heal failed", bucket=bucket, key=key, error=str(e))

    # ---------------------------------------------------------------- buckets
    async def _all_drives(self, fn) -> list:
        return [r for s in self.pools.all_sets for r in await s._each(fn)]

    def _majority(self) -> int:
        return sum(s.n for s in self.pools.all_sets) // 2 + 1

    async def make_bucket(self, bucket: str) -> None:
        res = await self._all_drives(lambda d: d.make_vol(bucket))
        exists = sum(isinstance(r, errors.VolumeExists) for r in res)
        ok = sum(not isinstance(r, BaseException) for r in res)
        if exists >= self._majority():
            raise errors.S3Error("BucketAlreadyOwnedByYou", bucket)
        if ok + exists < self._majority():
            await self._all_drives(lambda d: d.delete_vol(bucket))
            raise errors.InsufficientWriteQuorum()

    async def bucket_exists(self, bucket: str) -> bool:
        res = await self._all_drives(lambda d: d.stat_vol(bucket))
        found = sum(isinstance(r, dict) for r in res)
        missing = sum(isinstance(r, errors.VolumeNotFound) for r in res)
        return found > 0 and found > missing  # majority of the drives that answered

    async def list_buckets(self) -> list[dict]:
        res = await self._all_drives(lambda d: d.list_vols())
        counts = Counter(b for r in res if isinstance(r, list) for b in r)
        answered = sum(isinstance(r, list) for r in res)
        return [{"name": b} for b, c in sorted(counts.items()) if c > answered // 2]

    async def delete_bucket(self, bucket: str, force: bool = False) -> None:
        if not await self.bucket_exists(bucket):
            raise errors.S3Error("NoSuchBucket", bucket)
        if not force:
            for s in self.pools.all_sets:
                if await s.list_entries(bucket):
                    raise errors.S3Error("BucketNotEmpty", bucket)
        res = await self._all_drives(lambda d: d.delete_vol(bucket, force=True))
        if sum(not isinstance(r, BaseException) for r in res) < self._majority():
            raise errors.InsufficientWriteQuorum()

    async def heal_bucket(self, bucket: str) -> list[str]:
        created = []
        for s in self.pools.all_sets:
            created += await s.heal_bucket(bucket)
        return created

    # ---------------------------------------------------------------- objects
    async def put_object(self, bucket: str, key: str, reader: AsyncIterator[bytes],
                         opts: PutOpts, evaluate_replication: bool = True) -> ObjectInfo:
        s = await self.pools.set_for_new(bucket, key)
        fv = await s.put_object(bucket, key, reader, opts)
        oi = ObjectInfo(bucket, key, fv, s)
        if evaluate_replication and self.replication is not None and bucket != SYS_VOL:
            await self.replication.evaluate(bucket, key, fv, op="put")  # arrow #8
        return oi

    async def get_object_info(self, bucket: str, key: str, version_id: str | None = None) -> ObjectInfo:
        s = await self.pools.set_for_existing(bucket, key)
        fv, metas, mask = await s.get_object_info(bucket, key, version_id)
        if fv.is_delete_marker and not version_id:
            raise errors.S3Error("NoSuchKey", key, delete_marker=True, version_id=fv.version_id)
        latest = None
        for m, ok in zip(metas, mask):
            if ok and isinstance(m, FileMeta):
                latest = m.latest()
                break
        return ObjectInfo(bucket, key, fv, s, metas, mask,
                          is_latest=latest is None or latest.version_id == fv.version_id)

    def read(self, oi: ObjectInfo, offset: int = 0, length: int | None = None) -> AsyncIterator[bytes]:
        return oi.set.read_object(oi.bucket, oi.key, oi.version, oi.metas, oi.mask, offset, length)

    async def get_object(self, bucket: str, key: str, version_id: str | None = None,
                         offset: int = 0, length: int | None = None
                         ) -> tuple[ObjectInfo, AsyncIterator[bytes]]:
        oi = await self.get_object_info(bucket, key, version_id)
        return oi, self.read(oi, offset, length)

    async def get_object_bytes(self, bucket: str, key: str, version_id: str | None = None) -> bytes:
        oi, it = await self.get_object(bucket, key, version_id)
        return b"".join([c async for c in it])

    async def put_object_bytes(self, bucket: str, key: str, data: bytes,
                               opts: PutOpts | None = None) -> ObjectInfo:
        async def one():
            yield data
        return await self.put_object(bucket, key, one(), opts or PutOpts(), evaluate_replication=False)

    async def delete_object(self, bucket: str, key: str, version_id: str | None = None,
                            versioning: str = "Unversioned", evaluate_replication: bool = True) -> dict:
        s = await self.pools.set_for_existing(bucket, key)
        res = await s.delete_object(bucket, key, version_id, versioning)
        if evaluate_replication and self.replication is not None and bucket != SYS_VOL:
            await self.replication.evaluate_delete(bucket, key, res)  # arrow #8
        return res

    async def update_version_meta(self, bucket: str, key: str, version_id: str | None, **kw) -> None:
        s = await self.pools.set_for_existing(bucket, key)
        await s.update_version_meta(bucket, key, version_id, **kw)

    # ------------------------------------------------------------------ listing
    async def _entries(self, bucket: str, prefix: str) -> list[tuple[str, FileMeta, ErasureSet]]:
        res = await asyncio.gather(*[s.list_entries(bucket, prefix) for s in self.pools.all_sets],
                                   return_exceptions=True)
        out = []
        for s, r in zip(self.pools.all_sets, res):
            if isinstance(r, BaseException):
                raise r
            out.extend((k, fm, s) for k, fm in r)
        out.sort(key=lambda t: t[0])
        return out

    async def list_objects(self, bucket: str, prefix: str = "", delimiter: str = "",
                           marker: str = "", max_keys: int = 1000) -> ListResult:
        if bucket != SYS_VOL and not await self.bucket_exists(bucket):
            raise errors.S3Error("NoSuchBucket", bucket)
        result = ListResult()
        seen_prefixes: set[str] = set()
        count = 0
        for key, fm, s in await self._entries(bucket, prefix):
            if not key.startswith(prefix):
                continue
            latest = fm.latest()
            if latest is None or latest.is_delete_marker:
                continue
            if delimiter:
                rest = key[len(prefix):]
                pos = rest.find(delimiter)
                if pos >= 0:
                    cp = prefix + rest[:pos + len(delimiter)]
                    if cp in seen_prefixes or (marker and cp <= marker):
                        continue
                    if count >= max_keys:
                        result.is_truncated = True
                        break
                    seen_prefixes.add(cp)
                    result.prefixes.append(cp)
                    result.next_marker = cp
                    count += 1
                    continue
            if marker and key <= marker:
                continue
            if count >= max_keys:
                result.is_truncated = True
                break
            result.objects.append(ObjectInfo(bucket, key, latest, s))
            result.next_marker = key
            count += 1
        return result

    async def list_object_versions(self, bucket: str, prefix: str = "", delimiter: str = "",
                                   key_marker: str = "", version_marker: str = "",
                                   max_keys: int = 1000) -> ListResult:
        if not await self.bucket_exists(bucket):
            raise errors.S3Error("NoSuchBucket", bucket)
        result = ListResult()
        seen: set[str] = set()
        count = 0
        for key, fm, s in await self._entries(bucket, prefix):
            if delimiter:
                rest = key[len(prefix):]
                pos = rest.find(delimiter)
                if pos >= 0:
                    cp = prefix + rest[:pos + len(delimiter)]
                    if cp not in seen and not (key_marker and cp <= key_marker):
                        seen.add(cp)
                        result.prefixes.append(cp)
                    continue
            if key_marker and key < key_marker:
                continue
            versions = fm.versions
            if key_marker and key == key_marker:
                if not version_marker:
                    continue
                ids = [v.version_id for v in versions]
                versions = versions[ids.index(version_marker) + 1:] if version_marker in ids else []
            for i, v in enumerate(versions):
                if count >= max_keys:
                    result.is_truncated = True
                    return result
                result.objects.append(ObjectInfo(bucket, key, v, s, is_latest=(v is fm.versions[0])))
                result.next_marker, result.next_version_marker = key, v.version_id
                count += 1
        return result

    # --------------------------------------------------------------- multipart
    async def new_multipart_upload(self, bucket: str, key: str, opts: PutOpts) -> str:
        s = await self.pools.set_for_new(bucket, key)
        return await s.new_multipart_upload(bucket, key, opts)

    async def put_object_part(self, bucket, key, upload_id, part_number, reader, opts: PutOpts):
        s = await self.pools.set_for_new(bucket, key)
        return await s.put_object_part(bucket, key, upload_id, part_number, reader, opts)

    async def list_parts(self, bucket, key, upload_id):
        s = await self.pools.set_for_new(bucket, key)
        return await s.list_parts(bucket, key, upload_id)

    async def get_upload(self, bucket, key, upload_id) -> FileVersion:
        s = await self.pools.set_for_new(bucket, key)
        return await s.get_upload(bucket, key, upload_id)

    async def complete_multipart_upload(self, bucket, key, upload_id, parts, opts: PutOpts) -> ObjectInfo:
        s = await self.pools.set_for_new(bucket, key)
        fv = await s.complete_multipart_upload(bucket, key, upload_id, parts, opts)
        if self.replication is not None:
            await self.replication.evaluate(bucket, key, fv, op="put")  # arrow #8
        return ObjectInfo(bucket, key, fv, s)

    async def abort_multipart_upload(self, bucket, key, upload_id) -> None:
        s = await self.pools.set_for_new(bucket, key)
        await s.abort_multipart_upload(bucket, key, upload_id)

    async def list_multipart_uploads(self, bucket: str, prefix: str = "") -> list[FileVersion]:
        out = []
        for s in self.pools.all_sets:
            out += await s.list_multipart_uploads(bucket, prefix)
        out.sort(key=lambda v: (v.meta_sys.get("key", ""), v.mod_time_ns))
        return out

    # ------------------------------------------------------------------ heal
    async def heal_object(self, bucket: str, key: str, deep: bool = False, kind: str = "mrf") -> dict:
        """Arrow #10 target: Healing -> Storage Facade "repairs storage"."""
        s = await self.pools.set_for_existing(bucket, key)
        return await s.heal_object(bucket, key, deep=deep, kind=kind)

    # --------------------------------------------------------------- status
    async def storage_info(self) -> dict:
        sets = []
        for s in self.pools.all_sets:
            res = await s._each(lambda d: d.disk_info())
            drives = []
            for d, r in zip(s.drives, res):
                ep = d.endpoint if d else "?"
                if isinstance(r, dict):
                    drives.append({**r, "state": "ok"})
                    metrics.DRIVE_USED.labels(ep).set(r["used"])
                    metrics.DRIVE_TOTAL.labels(ep).set(r["total"])
                    metrics.DRIVE_ONLINE.labels(ep, str(s.index)).set(1)
                else:
                    drives.append({"endpoint": ep, "state": "offline", "error": type(r).__name__})
                    metrics.DRIVE_ONLINE.labels(ep, str(s.index)).set(0)
            online = sum(d["state"] == "ok" for d in drives)
            metrics.SET_ONLINE_DRIVES.labels(str(s.index)).set(online)
            sets.append({"pool": s.pool, "set": s.index, "online": online, "n": s.n,
                         "parity": s.parity, "read_quorum": s.read_quorum(),
                         "write_quorum": s.write_quorum(), "drives": drives})
        return {"sets": sets}

    async def has_write_quorum(self) -> bool:
        info = await self.storage_info()
        return all(s["online"] >= s["write_quorum"] for s in info["sets"])


def b64md5(raw: bytes) -> str:
    return base64.b64encode(raw).decode()
