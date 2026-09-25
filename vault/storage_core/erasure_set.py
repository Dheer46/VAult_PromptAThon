"""One erasure set: a fixed group of n drives. Turns object operations into quorum
operations on those drives (the Storage Facade's workhorse; arrow #7 "delegates disk I/O").
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import time
import uuid
import zlib
from dataclasses import dataclass, field
from typing import AsyncIterator, Callable

import msgpack

from .. import errors
from ..native import hash32
from ..observability import metrics
from ..observability.log import log
from .erasure import BLOCK_SIZE, ErasureCoder
from .filemeta import (INLINE_THRESHOLD, NULL_VERSION, ErasureInfo, FileMeta, FileVersion,
                       ObjectPart, load_metas, new_version_id, now_ns, resolve_filemeta,
                       resolve_version)
from .storage_api import HASH_LEN, SYS_VOL, StorageAPI

WRITER_QUEUE = 4
WRITER_TIMEOUT = 30.0
MIN_PART_SIZE = 5 * 1024 * 1024


def hash_order(key: str, n: int) -> list[int]:
    """Per-object permutation: shard index (1..n) for each drive position."""
    start = zlib.crc32(key.encode()) % n
    return [1 + ((start + i) % n) for i in range(1, n + 1)]


async def rechunk(it: AsyncIterator[bytes], size: int) -> AsyncIterator[bytes]:
    buf = bytearray()
    async for chunk in it:
        buf += chunk
        while len(buf) >= size:
            yield bytes(buf[:size])
            del buf[:size]
    if buf:
        yield bytes(buf)


def _etag_and_size(opts: "PutOpts", md5, total: int) -> tuple[str, int]:
    """etag/actual_size may be callables, resolved after the stream ends (the facade
    computes them over plaintext while the stored stream is encrypted)."""
    etag = opts.etag() if callable(opts.etag) else (opts.etag or md5.hexdigest())
    actual = opts.actual_size() if callable(opts.actual_size) else opts.actual_size
    return etag, (actual if actual >= 0 else total)


@dataclass
class PutOpts:
    version_id: str = NULL_VERSION
    versioned: bool = False
    parity: int | None = None
    meta_user: dict = field(default_factory=dict)
    meta_sys: dict = field(default_factory=dict)
    mod_time_ns: int = 0
    size: int = -1
    actual_size: int = -1  # plaintext size when the stream is encrypted
    content_md5: str | None = None  # base64, verified before commit
    content_sha256: str | None = None  # hex, verified before commit
    etag: str | None = None  # precomputed (e.g. md5 of plaintext before encryption)
    no_lock: bool = False
    inline: bool = True


class ErasureSet:
    def __init__(self, index: int, drives: list[StorageAPI | None], parity: int,
                 ns=None, block_size: int = BLOCK_SIZE, pool: int = 0):
        self.index = index
        self.pool = pool
        self.drives = drives
        self.n = len(drives)
        self.parity = min(parity, self.n // 2)
        self.ns = ns  # NSLock
        self.block_size = block_size
        self.on_partial: Callable[[str, str, str | None], None] | None = None  # MRF hook

    # --------------------------------------------------------------- quorum
    def k_for(self, parity: int | None = None) -> int:
        return self.n - (self.parity if parity is None else parity)

    def read_quorum(self, parity: int | None = None) -> int:
        return self.k_for(parity)

    def write_quorum(self, parity: int | None = None) -> int:
        m = self.parity if parity is None else parity
        k = self.n - m
        return k + 1 if k == m else k

    # -------------------------------------------------------------- helpers
    async def _each(self, fn, drives=None) -> list:
        drives = self.drives if drives is None else drives

        async def one(d):
            if d is None:
                raise errors.DiskNotFound("offline")
            return await fn(d)
        return await asyncio.gather(*[one(d) for d in drives], return_exceptions=True)

    async def _lock(self, resource: str, read=False):
        if self.ns is None:
            return None
        return await (self.ns.read(resource) if read else self.ns.write(resource))

    @staticmethod
    async def _unlock(lk):
        if lk is not None:
            await lk.release()

    def _partial(self, bucket: str, key: str, version_id: str | None) -> None:
        if self.on_partial:
            self.on_partial(bucket, key, version_id)

    async def read_metas(self, bucket: str, key: str) -> list[FileMeta | Exception]:
        return load_metas(await self._each(lambda d: d.read_meta(bucket, key)))

    def online_count(self) -> int:
        return sum(1 for d in self.drives if d is not None and not getattr(d, "faulty", False)
                   and getattr(d, "online", True))

    # ----------------------------------------------------------- write path
    async def _write_shards(self, reader: AsyncIterator[bytes], coder: ErasureCoder,
                            dist: list[int], tmp_rel: str, opts: PutOpts
                            ) -> tuple[list[bool], int, "hashlib._Hash", bytes | None, list | None]:
        """Encode the stream and write one shard file per drive.

        Returns (ok_mask, total_size, md5, first_block, inline_shards). When the whole
        stream fits in one small block, nothing is written to disk and inline_shards
        holds each drive's [hash][shard] bytes instead."""
        md5 = hashlib.md5()
        sha = hashlib.sha256() if opts.content_sha256 else None
        blocks = rechunk(reader, self.block_size)
        first = b""
        try:
            first = await blocks.__anext__()
        except StopAsyncIteration:
            pass
        second = None
        if len(first) == self.block_size:
            try:
                second = await blocks.__anext__()
            except StopAsyncIteration:
                pass

        def account(b: bytes):
            md5.update(b)
            if sha:
                sha.update(b)

        if opts.inline and second is None and len(first) <= INLINE_THRESHOLD:
            account(first)
            inline = [None] * self.n
            if first:
                shards = await coder.encode(first)
                for i in range(self.n):
                    s = shards[dist[i] - 1]
                    inline[i] = hash32(s) + s
            else:
                inline = [b""] * self.n
            self._verify_digests(md5, sha, opts)
            return [d is not None for d in self.drives], len(first), md5, first, inline

        queues: list[asyncio.Queue | None] = [asyncio.Queue(WRITER_QUEUE) if d else None
                                              for d in self.drives]
        ok = [d is not None for d in self.drives]

        async def drain(q):
            while True:
                item = await q.get()
                if item is None:
                    return
                yield item

        async def writer(i, d):
            try:
                await d.create_file(SYS_VOL, tmp_rel, -1, drain(queues[i]))
            except Exception as e:  # a failed drive must not stop the others
                ok[i] = False
                log.warning("shard write failed", endpoint=d.endpoint, error=str(e))
                queues[i] = None
                raise
        tasks = [asyncio.create_task(writer(i, d)) if d else None
                 for i, d in enumerate(self.drives)]

        async def feed(block: bytes):
            account(block)
            shards = await coder.encode(block)
            for i in range(self.n):
                q = queues[i]
                if q is None or not ok[i]:
                    continue
                if tasks[i].done():
                    ok[i] = False
                    continue
                try:
                    await asyncio.wait_for(q.put(shards[dist[i] - 1]), WRITER_TIMEOUT)
                except asyncio.TimeoutError:  # slow drive: give up on it, keep going
                    ok[i] = False
                    tasks[i].cancel()
                    queues[i] = None
            if sum(ok) < self.write_quorum(coder.m):
                raise errors.InsufficientWriteQuorum()

        total = 0
        try:
            if first:
                await feed(first)
                total += len(first)
            if second:
                await feed(second)
                total += len(second)
                async for block in blocks:
                    await feed(block)
                    total += len(block)
        finally:
            for i, q in enumerate(queues):
                if q is not None and tasks[i] and not tasks[i].done():
                    try:
                        await asyncio.wait_for(q.put(None), WRITER_TIMEOUT)
                    except asyncio.TimeoutError:
                        tasks[i].cancel()
            await asyncio.gather(*[t for t in tasks if t], return_exceptions=True)
        for i, t in enumerate(tasks):
            if t and (t.cancelled() or t.exception() is not None):
                ok[i] = False
        self._verify_digests(md5, sha, opts)
        return ok, total, md5, None, None

    @staticmethod
    def _verify_digests(md5, sha, opts: PutOpts) -> None:
        if opts.content_md5 and base64.b64encode(md5.digest()).decode() != opts.content_md5:
            raise errors.S3Error("BadDigest", "Content-MD5 mismatch")
        if sha and sha.hexdigest() != opts.content_sha256:
            raise errors.S3Error("XAmzContentSHA256Mismatch", "x-amz-content-sha256 mismatch")

    async def _cleanup_tmp(self, tmp_dir: str) -> None:
        await self._each(lambda d: d.delete(SYS_VOL, tmp_dir, recursive=True))

    async def _commit(self, bucket: str, key: str, fv: FileVersion, ok: list[bool],
                      inline: list | None, src_rel: str | None, wq: int) -> None:
        """Install fv on every ok drive (rename_data); roll back if below quorum."""
        async def commit_one(i: int):
            d = self.drives[i]
            try:
                old = await d.read_meta(bucket, key)
                try:
                    fm = FileMeta.unmarshal(old)
                except errors.FileCorrupt:
                    fm = FileMeta()
            except errors.FileNotFound:
                old, fm = None, FileMeta()
            v = fv.copy_for_drive(fv.erasure.distribution[i] if fv.erasure else 0,
                                  inline[i] if inline else None)
            freed = fm.add_version(v)
            await d.rename_data(SYS_VOL, src_rel or "", fm.marshal(), bucket, key)
            return old, freed

        idx = [i for i in range(self.n) if ok[i] and self.drives[i] is not None]
        results = await asyncio.gather(*[commit_one(i) for i in idx], return_exceptions=True)
        done = {i: r for i, r in zip(idx, results) if not isinstance(r, BaseException)}
        if len(done) < wq:
            metrics.QUORUM_FAILURES.labels("write").inc()
            # undo on the drives that did succeed
            for i, (old, _) in done.items():
                d = self.drives[i]
                try:
                    if old is None:
                        await d.delete(bucket, key, recursive=True)
                    else:
                        await d.write_meta(bucket, key, old)
                        if fv.data_dir:
                            await d.delete(bucket, f"{key}/{fv.data_dir}", recursive=True)
                except Exception:
                    pass
            raise errors.InsufficientWriteQuorum(f"{len(done)}/{wq} drives committed")
        for i, (_, freed) in done.items():
            for dd in freed:
                try:
                    await self.drives[i].delete(bucket, f"{key}/{dd}", recursive=True)
                except Exception:
                    pass
        if len(done) < self.n:
            self._partial(bucket, key, fv.version_id)

    async def put_object(self, bucket: str, key: str, reader: AsyncIterator[bytes],
                         opts: PutOpts) -> FileVersion:
        m = self.parity if opts.parity is None else min(opts.parity, self.n // 2)
        coder = ErasureCoder(self.n - m, m, self.block_size)
        dist = hash_order(key, self.n)
        wq = self.write_quorum(m)
        if sum(d is not None for d in self.drives) < wq:
            metrics.QUORUM_FAILURES.labels("write").inc()
            raise errors.InsufficientWriteQuorum()
        data_dir = str(uuid.uuid4())
        tmp_dir = f"tmp/{uuid.uuid4()}"
        tmp_rel = f"{tmp_dir}/{data_dir}/part.1"
        lk = None if opts.no_lock else await self._lock(f"{bucket}/{key}")
        try:
            try:
                ok, total, md5, _, inline = await self._write_shards(reader, coder, dist, tmp_rel, opts)
            except BaseException:
                await self._cleanup_tmp(tmp_dir)
                raise
            if opts.size >= 0 and total != opts.size:
                await self._cleanup_tmp(tmp_dir)
                raise errors.S3Error("IncompleteBody", f"expected {opts.size} bytes, got {total}", 400)
            if sum(ok) < wq:
                await self._cleanup_tmp(tmp_dir)
                metrics.QUORUM_FAILURES.labels("write").inc()
                raise errors.InsufficientWriteQuorum()
            if lk:
                lk.check()
            etag, actual = _etag_and_size(opts, md5, total)
            fv = FileVersion(
                version_id=opts.version_id, type="object", mod_time_ns=opts.mod_time_ns or now_ns(),
                size=total, data_dir="" if inline else data_dir,
                erasure=ErasureInfo(k=coder.k, m=coder.m, block_size=self.block_size,
                                    distribution=dist),
                parts=[ObjectPart(1, total, actual, etag)],
                meta_sys=dict(opts.meta_sys), meta_user={**opts.meta_user, "etag": etag})
            await self._commit(bucket, key, fv, ok, inline,
                               None if inline else f"{tmp_dir}/{data_dir}", wq)
            if not inline:
                await self._cleanup_tmp(tmp_dir)
            return fv
        finally:
            await self._unlock(lk)

    # ------------------------------------------------------------ read path
    async def get_object_info(self, bucket: str, key: str, version_id: str | None = None,
                              ) -> tuple[FileVersion, list[FileMeta | Exception], list[bool]]:
        metas = await self.read_metas(bucket, key)
        if sum(isinstance(m, errors.VolumeNotFound) for m in metas) >= self.read_quorum():
            raise errors.S3Error("NoSuchBucket", bucket)
        try:
            fv, mask = resolve_version(metas, version_id, self.read_quorum())
        except errors.InsufficientReadQuorum:
            metrics.QUORUM_FAILURES.labels("read").inc()
            raise
        if fv is None:
            if version_id:
                raise errors.S3Error("NoSuchVersion", f"{key} version {version_id}")
            raise errors.S3Error("NoSuchKey", key)
        answered = [not isinstance(m, Exception) or isinstance(m, errors.FileNotFound) for m in metas]
        if any(a and not ok for a, ok in zip(answered, mask)):
            self._partial(bucket, key, None)  # outdated drives: queue a heal
        return fv, metas, mask

    def _block_plan(self, fv: FileVersion, offset: int, length: int):
        """Yield (part, block_index, block_len, start_in_block, end_in_block)."""
        pos = 0
        end = offset + length
        for part in fv.parts:
            if pos >= end:
                break
            if pos + part.size <= offset:
                pos += part.size
                continue
            full, last = divmod(part.size, fv.erasure.block_size)
            lens = [fv.erasure.block_size] * full + ([last] if last else [])
            for bi, bl in enumerate(lens):
                b0, b1 = pos, pos + bl
                pos = b1
                if b1 <= offset or b0 >= end:
                    continue
                yield part, bi, bl, max(offset, b0) - b0, min(end, b1) - b0
            pos = pos  # parts are contiguous

    async def _read_block(self, bucket: str, key: str, fv: FileVersion, part: ObjectPart,
                          bi: int, bl: int, mask: list[bool], coder: ErasureCoder,
                          bad: set[int]) -> bytes:
        ss_full = coder.shard_size(fv.erasure.block_size)
        ss = coder.shard_size(bl)
        dist = fv.erasure.distribution
        path = f"{key}/{fv.data_dir}/part.{part.number}"
        # prefer data shards (index <= k), then parity
        order = sorted([i for i in range(self.n) if mask[i] and i not in bad and self.drives[i]],
                       key=lambda i: dist[i])
        shards: list[bytes | None] = [None] * self.n
        got = 0
        pending = list(order)
        while got < coder.k:
            need = coder.k - got
            if len(pending) < need:
                raise errors.InsufficientReadQuorum(f"{bucket}/{key}: only {got} shards readable")
            batch, pending = pending[:need], pending[need:]
            res = await asyncio.gather(*[
                self.drives[i].read_file(bucket, path, bi * ss_full, ss, ss_full) for i in batch],
                return_exceptions=True)
            for i, r in zip(batch, res):
                if isinstance(r, BaseException):
                    bad.add(i)
                    if isinstance(r, errors.FileCorrupt):
                        log.warning("bitrot detected", bucket=bucket, key=key, drive=i)
                    self._partial(bucket, key, fv.version_id)
                else:
                    shards[dist[i] - 1] = r
                    got += 1
        return await coder.decode(shards, bl)

    async def _inline_data(self, fv: FileVersion, metas, mask, coder: ErasureCoder,
                           bucket: str, key: str) -> bytes:
        if fv.size == 0:
            return b""
        shards: list[bytes | None] = [None] * self.n
        got = 0
        for i, (fm, ok) in enumerate(zip(metas, mask)):
            if not ok or not isinstance(fm, FileMeta):
                continue
            v = fm.find(fv.version_id)
            raw = v.inline_data if v else None
            if not raw or len(raw) < HASH_LEN or hash32(raw[HASH_LEN:]) != raw[:HASH_LEN]:
                self._partial(bucket, key, fv.version_id)
                continue
            shards[fv.erasure.distribution[i] - 1] = raw[HASH_LEN:]
            got += 1
        if got < coder.k:
            raise errors.InsufficientReadQuorum(f"{bucket}/{key}: inline shards")
        return await coder.decode(shards, fv.size)

    async def read_object(self, bucket: str, key: str, fv: FileVersion, metas, mask,
                          offset: int = 0, length: int | None = None) -> AsyncIterator[bytes]:
        """Stream [offset, offset+length) of the stored bytes."""
        if length is None:
            length = fv.size - offset
        if length <= 0 or fv.size == 0:
            return
        coder = ErasureCoder(fv.erasure.k, fv.erasure.m, fv.erasure.block_size)
        if fv.is_inline:
            data = await self._inline_data(fv, metas, mask, coder, bucket, key)
            yield data[offset:offset + length]
            return
        bad: set[int] = set()
        for part, bi, bl, s, e in self._block_plan(fv, offset, length):
            block = await self._read_block(bucket, key, fv, part, bi, bl, mask, coder, bad)
            yield block[s:e]

    # ---------------------------------------------------------------- delete
    async def delete_object(self, bucket: str, key: str, version_id: str | None,
                            versioning: str = "Unversioned") -> dict:
        """versioning: "Unversioned" | "Enabled" | "Suspended"."""
        lk = await self._lock(f"{bucket}/{key}")
        try:
            metas = await self.read_metas(bucket, key)
            wq = self.write_quorum()
            result = {"delete_marker": False, "version_id": None, "deleted": None}
            dm_vid = None
            if not version_id and versioning == "Enabled":
                dm_vid = new_version_id()
            elif not version_id and versioning == "Suspended":
                dm_vid = NULL_VERSION
            mod = now_ns()

            async def one(i: int):
                d = self.drives[i]
                fm = metas[i]
                if isinstance(fm, errors.FileNotFound):
                    fm = FileMeta()
                elif isinstance(fm, Exception):
                    raise fm
                freed: list[str] = []
                if dm_vid:
                    dm = FileVersion(version_id=dm_vid, type="delete_marker", mod_time_ns=mod)
                    freed = fm.add_version(dm)
                else:
                    target = version_id or NULL_VERSION
                    v = fm.delete_version(target)
                    if v is None and not version_id:
                        latest = fm.latest()
                        if latest and latest.version_id == NULL_VERSION:
                            v = fm.delete_version(NULL_VERSION)
                    if v is not None and v.data_dir:
                        freed.append(v.data_dir)
                    if v is not None:
                        result["deleted"] = v
                if fm.versions:
                    await d.write_meta(bucket, key, fm.marshal())
                    for dd in freed:
                        try:
                            await d.delete(bucket, f"{key}/{dd}", recursive=True)
                        except errors.FileNotFound:
                            pass
                else:
                    try:
                        await d.delete(bucket, key, recursive=True)
                    except errors.FileNotFound:
                        pass
                return True

            res = await asyncio.gather(*[one(i) for i in range(self.n)], return_exceptions=True)
            okc = sum(r is True for r in res)
            if okc < wq:
                metrics.QUORUM_FAILURES.labels("write").inc()
                raise errors.InsufficientWriteQuorum()
            if okc < self.n:
                self._partial(bucket, key, None)
            if dm_vid:
                result.update(delete_marker=True, version_id=dm_vid)
            elif version_id:
                d = result["deleted"]
                result.update(version_id=version_id,
                              delete_marker=bool(d and d.is_delete_marker))
            return result
        finally:
            await self._unlock(lk)

    async def update_version_meta(self, bucket: str, key: str, version_id: str | None,
                                  meta_sys: dict | None = None, meta_user: dict | None = None,
                                  drop_data: bool = False, storage_class: str | None = None,
                                  lock: bool = True) -> None:
        """Quorum-update metadata of one version (replication status, tiering, tags)."""
        lk = await self._lock(f"{bucket}/{key}") if lock else None
        try:
            fv, metas, mask = await self.get_object_info(bucket, key, version_id)

            async def one(i):
                fm = metas[i]
                if not mask[i] or not isinstance(fm, FileMeta):
                    raise errors.FileNotFound("stale")
                v = fm.find(fv.version_id)
                if meta_sys:
                    v.meta_sys.update(meta_sys)
                if meta_user:
                    v.meta_user.update(meta_user)
                if storage_class:
                    v.meta_user["x-amz-storage-class"] = storage_class
                old_dd = v.data_dir
                if drop_data:
                    v.data_dir, v.inline_data = "", None
                await self.drives[i].write_meta(bucket, key, fm.marshal())
                if drop_data and old_dd:
                    try:
                        await self.drives[i].delete(bucket, f"{key}/{old_dd}", recursive=True)
                    except errors.FileNotFound:
                        pass
                return True
            res = await asyncio.gather(*[one(i) for i in range(self.n)], return_exceptions=True)
            if sum(r is True for r in res) < self.write_quorum():
                raise errors.InsufficientWriteQuorum()
        finally:
            await self._unlock(lk)

    # ------------------------------------------------------------------ list
    async def list_entries(self, bucket: str, prefix: str = "") -> list[tuple[str, FileMeta]]:
        """Walk all online drives, merge, and resolve each key by quorum."""
        async def walk(d):
            return [kv async for kv in d.walk_dir(bucket, prefix)]
        res = await self._each(walk)
        answered = [r for r in res if not isinstance(r, BaseException)]
        if sum(isinstance(r, errors.VolumeNotFound) for r in res) >= self.read_quorum():
            raise errors.S3Error("NoSuchBucket", bucket)
        if len(answered) < self.read_quorum():
            metrics.QUORUM_FAILURES.labels("read").inc()
            raise errors.InsufficientReadQuorum("listing")
        per_key: dict[str, list] = {}
        for di, r in enumerate(answered):
            for k, raw in r:
                per_key.setdefault(k, [errors.FileNotFound(k)] * len(answered))[di] = raw
        out = []
        for k in sorted(per_key):
            metas = load_metas(per_key[k])
            try:
                fm, _ = resolve_filemeta(metas, min(self.read_quorum(), len(answered)))
            except errors.InsufficientReadQuorum:
                # versions still in flux: fall back to the latest-version agreement
                try:
                    v, mask = resolve_version(metas, None, min(self.read_quorum(), len(answered)))
                except errors.InsufficientReadQuorum:
                    continue
                if v is None:
                    continue
                fm = next(m for m, ok in zip(metas, mask) if ok)
            if fm is not None and fm.versions:
                out.append((k, fm))
        return out

    # ------------------------------------------------------------- multipart
    @staticmethod
    def upload_path(bucket: str, key: str, upload_id: str) -> str:
        h = hashlib.sha256(f"{bucket}/{key}".encode()).hexdigest()
        return f"multipart/{h}/{upload_id}"

    async def new_multipart_upload(self, bucket: str, key: str, opts: PutOpts) -> str:
        upload_id = str(uuid.uuid4())
        m = self.parity if opts.parity is None else min(opts.parity, self.n // 2)
        fv = FileVersion(version_id=upload_id, mod_time_ns=now_ns(), data_dir=str(uuid.uuid4()),
                         erasure=ErasureInfo(k=self.n - m, m=m, block_size=self.block_size,
                                             distribution=hash_order(key, self.n)),
                         meta_sys={**opts.meta_sys, "bucket": bucket, "key": key},
                         meta_user=dict(opts.meta_user))
        raw = FileMeta([fv]).marshal()
        res = await self._each(lambda d: d.write_meta(SYS_VOL, self.upload_path(bucket, key, upload_id), raw))
        if sum(not isinstance(r, BaseException) for r in res) < self.write_quorum(m):
            raise errors.InsufficientWriteQuorum()
        return upload_id

    async def get_upload(self, bucket: str, key: str, upload_id: str) -> FileVersion:
        metas = await self.read_metas(SYS_VOL, self.upload_path(bucket, key, upload_id))
        try:
            fv, _ = resolve_version(metas, upload_id, self.read_quorum())
        except errors.InsufficientReadQuorum:
            fv = None
        if fv is None:
            raise errors.S3Error("NoSuchUpload", upload_id)
        return fv

    async def put_object_part(self, bucket: str, key: str, upload_id: str, part_number: int,
                              reader: AsyncIterator[bytes], opts: PutOpts) -> ObjectPart:
        up = await self.get_upload(bucket, key, upload_id)
        coder = ErasureCoder(up.erasure.k, up.erasure.m, up.erasure.block_size)
        dist = up.erasure.distribution
        wq = self.write_quorum(up.erasure.m)
        tmp_dir = f"tmp/{uuid.uuid4()}"
        tmp_rel = f"{tmp_dir}/{up.data_dir}/part.{part_number}"
        popts = PutOpts(**{**opts.__dict__, "inline": False})
        try:
            ok, total, md5, _, _ = await self._write_shards(reader, coder, dist, tmp_rel, popts)
        except BaseException:
            await self._cleanup_tmp(tmp_dir)
            raise
        if popts.size >= 0 and total != popts.size:
            await self._cleanup_tmp(tmp_dir)
            raise errors.S3Error("IncompleteBody", "short part body", 400)
        etag, actual = _etag_and_size(opts, md5, total)
        part = ObjectPart(part_number, total, actual, etag)
        pmeta = msgpack.packb(part.__dict__)
        dest = self.upload_path(bucket, key, upload_id)

        async def one(i):
            d = self.drives[i]
            await d.write_all(SYS_VOL, f"{tmp_dir}/{up.data_dir}/part.{part_number}.meta", pmeta)
            await d.rename_data(SYS_VOL, f"{tmp_dir}/{up.data_dir}", b"", SYS_VOL, dest)
            return True
        idx = [i for i in range(self.n) if ok[i] and self.drives[i]]
        res = await asyncio.gather(*[one(i) for i in idx], return_exceptions=True)
        await self._cleanup_tmp(tmp_dir)
        if sum(r is True for r in res) < wq:
            raise errors.InsufficientWriteQuorum()
        return part

    async def list_parts(self, bucket: str, key: str, upload_id: str) -> list[ObjectPart]:
        up = await self.get_upload(bucket, key, upload_id)
        base = f"{self.upload_path(bucket, key, upload_id)}/{up.data_dir}"

        async def read_parts(d):
            names = await d.list_dir(SYS_VOL, base)
            out = {}
            for nm in names:
                if nm.endswith(".meta"):
                    p = ObjectPart(**msgpack.unpackb(await d.read_all(SYS_VOL, f"{base}/{nm}")))
                    out[p.number] = p
            return out
        res = await self._each(read_parts)
        votes: dict[tuple, int] = {}
        parts: dict[tuple, ObjectPart] = {}
        for r in res:
            if isinstance(r, BaseException):
                continue
            for p in r.values():
                sig = (p.number, p.etag, p.size)
                votes[sig] = votes.get(sig, 0) + 1
                parts[sig] = p
        best: dict[int, tuple] = {}
        for sig, c in votes.items():
            if c >= self.read_quorum(up.erasure.m) and (sig[0] not in best or c > votes[best[sig[0]]]):
                best[sig[0]] = sig
        return [parts[best[n]] for n in sorted(best)]

    async def complete_multipart_upload(self, bucket: str, key: str, upload_id: str,
                                        requested: list[tuple[int, str]], opts: PutOpts) -> FileVersion:
        lk = await self._lock(f"{bucket}/{key}")
        try:
            up = await self.get_upload(bucket, key, upload_id)
            have = {p.number: p for p in await self.list_parts(bucket, key, upload_id)}
            if not requested:
                raise errors.S3Error("MalformedXML", "no parts")
            chosen: list[ObjectPart] = []
            last = 0
            for i, (num, etag) in enumerate(requested):
                if num <= last:
                    raise errors.S3Error("InvalidPartOrder", "parts must be ascending")
                last = num
                p = have.get(num)
                if p is None or p.etag.strip('"') != etag.strip('"'):
                    raise errors.S3Error("InvalidPart", f"part {num}")
                if i < len(requested) - 1 and p.actual_size < MIN_PART_SIZE:
                    raise errors.S3Error("EntityTooSmall", f"part {num} is smaller than 5 MiB")
                chosen.append(p)
            md5s = b"".join(bytes.fromhex(p.etag.strip('"').split("-")[0]) for p in chosen)
            etag = f"{hashlib.md5(md5s).hexdigest()}-{len(chosen)}"
            fv = FileVersion(
                version_id=opts.version_id, mod_time_ns=now_ns(), size=sum(p.size for p in chosen),
                data_dir=up.data_dir, erasure=up.erasure, parts=chosen,
                meta_sys={**{k: v for k, v in up.meta_sys.items() if k not in ("bucket", "key")},
                          **opts.meta_sys},
                meta_user={**up.meta_user, **opts.meta_user, "etag": etag})
            fv.meta_sys["x-vault-actual-size"] = sum(p.actual_size for p in chosen)
            upath = self.upload_path(bucket, key, upload_id)
            keep = {f"part.{p.number}" for p in chosen}

            async def prune(d):
                names = await d.list_dir(SYS_VOL, f"{upath}/{up.data_dir}")
                for nm in names:
                    if nm not in keep:
                        await d.delete(SYS_VOL, f"{upath}/{up.data_dir}/{nm}")
                return True
            pr = await self._each(prune)
            ok = [r is True for r in pr]
            await self._commit(bucket, key, fv, ok, None, f"{upath}/{up.data_dir}",
                               self.write_quorum(up.erasure.m))
            await self._each(lambda d: d.delete(SYS_VOL, upath, recursive=True))
            return fv
        finally:
            await self._unlock(lk)

    async def abort_multipart_upload(self, bucket: str, key: str, upload_id: str) -> None:
        await self.get_upload(bucket, key, upload_id)
        await self._each(lambda d: d.delete(SYS_VOL, self.upload_path(bucket, key, upload_id),
                                            recursive=True))

    async def list_multipart_uploads(self, bucket: str, prefix: str = "") -> list[FileVersion]:
        entries = []
        try:
            entries = await self.list_entries(SYS_VOL, "multipart/")
        except errors.S3Error:
            return []
        out = []
        for _, fm in entries:
            v = fm.latest()
            if v and v.meta_sys.get("bucket") == bucket and v.meta_sys.get("key", "").startswith(prefix):
                out.append(v)
        return out

    # ------------------------------------------------------------------ heal
    async def heal_object(self, bucket: str, key: str, deep: bool = False,
                          kind: str = "mrf") -> dict:
        """Rebuild missing/outdated/corrupt shards and metadata on this set's drives
        (arrow #10's target, via StorageFacade.heal_object)."""
        lk = await self._lock(f"{bucket}/{key}")
        try:
            return await self._heal_object(bucket, key, deep, kind)
        finally:
            await self._unlock(lk)

    async def _heal_object(self, bucket, key, deep, kind) -> dict:
        metas = await self.read_metas(bucket, key)
        truth, mask = resolve_filemeta(metas, self.read_quorum())
        result = {"bucket": bucket, "key": key, "healed": [], "dangling_removed": [], "bytes": 0}
        if truth is None:
            # quorum positively says "doesn't exist": delete leftovers on stale drives
            for i, fm in enumerate(metas):
                if isinstance(fm, FileMeta) and fm.versions:
                    try:
                        await self.drives[i].delete(bucket, key, recursive=True)
                        result["dangling_removed"].append(self.drives[i].endpoint)
                    except Exception:
                        pass
            return result

        good = [i for i in range(self.n) if mask[i] and self.drives[i] is not None]
        corrupt: dict[int, set[str]] = {}  # drive -> version ids needing data
        # deep: verify shard files on the drives that agree on metadata
        if deep:
            for v in truth.versions:
                if v.is_delete_marker or not v.data_dir:
                    continue
                coder = ErasureCoder(v.erasure.k, v.erasure.m, v.erasure.block_size)

                async def verify(i, v=v, coder=coder):
                    for p in v.parts:
                        okf = await self.drives[i].verify_file(
                            bucket, f"{key}/{v.data_dir}/part.{p.number}",
                            coder.shard_size(v.erasure.block_size), coder.shard_file_size(p.size))
                        if not okf:
                            return False
                    return True
                res = await asyncio.gather(*[verify(i) for i in good], return_exceptions=True)
                for i, r in zip(good, res):
                    if r is not True:
                        corrupt.setdefault(i, set()).add(v.version_id)
        # inline shards: verify their hashes on agreeing drives too
        for i in good:
            fm = metas[i]
            for v in fm.versions:
                if v.inline_data and hash32(v.inline_data[HASH_LEN:]) != v.inline_data[:HASH_LEN]:
                    corrupt.setdefault(i, set()).add(v.version_id)

        sources = [i for i in good if i not in corrupt]
        targets = [i for i in range(self.n) if self.drives[i] is not None
                   and (not mask[i] or i in corrupt)
                   and not isinstance(metas[i], errors.DiskNotFound)]
        if not targets:
            return result

        for t in targets:
            d = self.drives[t]
            own = metas[t] if isinstance(metas[t], FileMeta) else FileMeta()
            new_fm = FileMeta()
            tmp_dir = f"tmp/{uuid.uuid4()}"
            try:
                for v in truth.versions:
                    idx = v.erasure.distribution[t] if v.erasure else 0
                    nv = FileVersion.from_dict(v.to_dict())
                    nv.inline_data = None
                    if nv.erasure:
                        nv.erasure.index = idx
                    mine = own.find(v.version_id)
                    needs_data = (mine is None or mine.data_dir != v.data_dir
                                  or v.version_id in corrupt.get(t, set()))
                    if v.is_delete_marker:
                        pass
                    elif v.is_inline or (v.size == 0 and not v.data_dir):
                        nv.inline_data = await self._heal_inline(v, metas, sources, t)
                    elif v.data_dir and needs_data:
                        result["bytes"] += await self._heal_parts(bucket, key, v, sources, t, tmp_dir)
                        await d.rename_data(SYS_VOL, f"{tmp_dir}/{v.data_dir}", b"", bucket, key)
                    new_fm.versions.append(nv)
                new_fm._sort()
                await d.write_meta(bucket, key, new_fm.marshal())
                for dd in own.data_dirs() - truth.data_dirs():
                    try:
                        await d.delete(bucket, f"{key}/{dd}", recursive=True)
                    except Exception:
                        pass
                result["healed"].append(d.endpoint)
                metrics.HEAL_OBJECTS.labels(kind, "ok").inc()
            except Exception as e:
                metrics.HEAL_OBJECTS.labels(kind, "failed").inc()
                log.warning("heal failed", bucket=bucket, key=key, drive=d.endpoint, error=str(e))
            finally:
                try:
                    await d.delete(SYS_VOL, tmp_dir, recursive=True)
                except Exception:
                    pass
        metrics.HEAL_BYTES.labels(kind).inc(result["bytes"])
        if result["healed"]:
            log.info("object healed", bucket=bucket, key=key, drives=result["healed"], kind=kind)
        return result

    async def _heal_inline(self, v: FileVersion, metas, sources: list[int], t: int) -> bytes:
        if v.size == 0:
            return b""
        coder = ErasureCoder(v.erasure.k, v.erasure.m, v.erasure.block_size)
        shards: list[bytes | None] = [None] * self.n
        for i in sources:
            sv = metas[i].find(v.version_id)
            if sv and sv.inline_data and hash32(sv.inline_data[HASH_LEN:]) == sv.inline_data[:HASH_LEN]:
                shards[v.erasure.distribution[i] - 1] = sv.inline_data[HASH_LEN:]
        if sum(s is not None for s in shards) < coder.k:
            raise errors.InsufficientReadQuorum("never heal from fewer than k verified shards")
        full = await coder.heal(shards, coder.shard_size(v.size))
        s = full[v.erasure.distribution[t] - 1]
        return hash32(s) + s

    async def _heal_parts(self, bucket, key, v: FileVersion, sources: list[int], t: int,
                          tmp_dir: str) -> int:
        coder = ErasureCoder(v.erasure.k, v.erasure.m, v.erasure.block_size)
        dist = v.erasure.distribution
        written = 0
        for p in v.parts:
            path = f"{key}/{v.data_dir}/part.{p.number}"
            ss_full = coder.shard_size(v.erasure.block_size)
            bad: set[int] = set()

            async def blocks(p=p, path=path):
                nonlocal written
                for bi, bl in enumerate(coder.block_lengths(p.size)):
                    ss = coder.shard_size(bl)
                    shards: list[bytes | None] = [None] * self.n
                    got = 0
                    for i in sorted([s for s in sources if s not in bad], key=lambda i: dist[i]):
                        if got >= coder.k:
                            break
                        try:
                            shards[dist[i] - 1] = await self.drives[i].read_file(
                                bucket, path, bi * ss_full, ss, ss_full)
                            got += 1
                        except Exception:
                            bad.add(i)
                    if got < coder.k:
                        raise errors.InsufficientReadQuorum("never heal from fewer than k verified shards")
                    full = await coder.heal(shards, ss)
                    written += ss
                    yield full[dist[t] - 1]
            await self.drives[t].create_file(SYS_VOL, f"{tmp_dir}/{v.data_dir}/part.{p.number}",
                                             coder.shard_file_size(p.size), blocks())
        return written

    async def heal_bucket(self, bucket: str) -> list[str]:
        """Create the bucket dir on drives that miss it."""
        res = await self._each(lambda d: d.stat_vol(bucket))
        exists = sum(not isinstance(r, BaseException) for r in res)
        created = []
        if exists >= self.read_quorum() or bucket == SYS_VOL:
            for d, r in zip(self.drives, res):
                if d is not None and isinstance(r, errors.VolumeNotFound):
                    try:
                        await d.make_vol(bucket)
                        created.append(d.endpoint)
                    except errors.VolumeExists:
                        pass
        return created
