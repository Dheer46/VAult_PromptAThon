"""One local drive (diagram box: Disk Storage).

On-disk layout per drive:
    <root>/.vault.sys/format.json
    <root>/.vault.sys/tmp/<uuid>/<data_dir>/part.N     in-flight writes
    <root>/<bucket>/<key>/xl.meta                       every version of the object
    <root>/<bucket>/<key>/<data_dir>/part.N             [hash32][block] pairs

Rules: all blocking I/O runs on a per-drive thread pool; files are fsynced (and
their parent directory) before success; nothing is overwritten in place; a hung
or failing drive is marked faulty and raises DiskNotFound until a probe succeeds.
"""
from __future__ import annotations

import asyncio
import errno
import os
import re
import shutil
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import AsyncIterator

from .. import errors
from ..native import hash32
from ..observability import metrics
from .storage_api import HASH_LEN, META_FILE, SYS_VOL, StorageAPI

_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_SYS_SKIP = {"tmp", "multipart", "scanner", "repl-queue", "tier-journal", "queues"}

ERROR_THRESHOLD = 10
OP_TIMEOUT = 30.0
PROBE_INTERVAL = 10.0


def _fsync_dir(path: str) -> None:
    if os.name == "nt":  # directories can't be opened for fsync on Windows
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_atomic(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{uuid.uuid4().hex}.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(path))


class DiskStore(StorageAPI):
    is_local = True

    def __init__(self, root: str, endpoint: str | None = None):
        self.root = os.path.abspath(root)
        self.endpoint = endpoint or self.root
        self.drive_id = ""
        self.faulty = False
        self.healing = False
        self._errors = 0
        self._last_latency = 0.0
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix=f"disk")
        self._probe_task: asyncio.Task | None = None
        os.makedirs(os.path.join(self.root, SYS_VOL, "tmp"), exist_ok=True)

    # ------------------------------------------------------------------ helpers
    def _p(self, bucket: str, path: str = "") -> str:
        base = os.path.join(self.root, bucket)
        full = os.path.normpath(os.path.join(base, path)) if path else os.path.normpath(base)
        if not (full == self.root or full.startswith(self.root + os.sep)):
            raise PermissionError("invalid path")  # blocks "../" path traversal
        if bucket and not (full == os.path.normpath(base) or full.startswith(os.path.normpath(base) + os.sep)):
            raise PermissionError("invalid path")
        return full

    async def _run(self, op: str, fn, *args):
        if self.faulty:
            raise errors.DiskNotFound(self.endpoint)
        loop = asyncio.get_running_loop()
        t0 = time.monotonic()
        try:
            result = await asyncio.wait_for(loop.run_in_executor(self._pool, fn, *args), OP_TIMEOUT)
        except asyncio.TimeoutError:
            self._mark_faulty(f"{op} timed out")
            raise errors.DiskNotFound(self.endpoint)
        except OSError as e:
            if e.errno in (errno.EIO, errno.EROFS):
                self._errors += 1
                metrics.DRIVE_IO_ERRORS.labels(self.endpoint, op).inc()
                if self._errors >= ERROR_THRESHOLD:
                    self._mark_faulty(f"{self._errors} I/O errors")
                raise errors.DiskNotFound(self.endpoint) from e
            if e.errno == errno.ENOSPC:
                raise errors.DiskFull(self.endpoint) from e
            raise
        finally:
            self._last_latency = time.monotonic() - t0
        return result

    def _mark_faulty(self, why: str) -> None:
        if not self.faulty:
            from ..observability.log import log
            log.warning("drive marked faulty", endpoint=self.endpoint, reason=why)
        self.faulty = True
        if self._probe_task is None or self._probe_task.done():
            try:
                self._probe_task = asyncio.get_running_loop().create_task(self._probe_loop())
            except RuntimeError:
                pass

    async def _probe_loop(self) -> None:
        while self.faulty:
            await asyncio.sleep(PROBE_INTERVAL)
            try:
                probe = os.path.join(self.root, SYS_VOL, "tmp", f"probe-{uuid.uuid4().hex}")
                await asyncio.wait_for(asyncio.to_thread(self._probe, probe), 5)
                self.faulty, self._errors = False, 0
            except Exception:
                continue

    @staticmethod
    def _probe(path: str) -> None:
        with open(path, "wb") as f:
            f.write(b"probe")
            os.fsync(f.fileno())
        with open(path, "rb") as f:
            assert f.read() == b"probe"
        os.remove(path)

    def clean_tmp(self) -> None:
        """Anything in tmp on startup is from a crashed write."""
        tmp = os.path.join(self.root, SYS_VOL, "tmp")
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp, exist_ok=True)

    # --------------------------------------------------------------- disk info
    async def disk_info(self) -> dict:
        def _info():
            if not os.path.isdir(self.root):
                raise errors.DiskNotFound(self.endpoint)
            u = shutil.disk_usage(self.root)
            formatted = os.path.exists(os.path.join(self.root, SYS_VOL, "format.json"))
            return {"total": u.total, "free": u.free, "used": u.total - u.free,
                    "formatted": formatted}
        info = await self._run("disk_info", _info)
        info.update(endpoint=self.endpoint, id=self.drive_id, healing=self.healing,
                    latency_ms=round(self._last_latency * 1000, 3), online=True)
        return info

    # ------------------------------------------------------------------ volumes
    async def make_vol(self, bucket: str) -> None:
        def _mk():
            p = self._p(bucket)
            if os.path.isdir(p):
                raise errors.VolumeExists(bucket)
            os.makedirs(p)
            _fsync_dir(self.root)
        await self._run("make_vol", _mk)

    async def list_vols(self) -> list[str]:
        def _ls():
            return sorted(d for d in os.listdir(self.root)
                          if d != SYS_VOL and os.path.isdir(os.path.join(self.root, d)))
        return await self._run("list_vols", _ls)

    async def stat_vol(self, bucket: str) -> dict:
        def _st():
            p = self._p(bucket)
            if not os.path.isdir(p):
                raise errors.VolumeNotFound(bucket)
            return {"name": bucket, "created": os.stat(p).st_mtime}
        return await self._run("stat_vol", _st)

    async def delete_vol(self, bucket: str, force: bool = False) -> None:
        def _rm():
            p = self._p(bucket)
            if not os.path.isdir(p):
                raise errors.VolumeNotFound(bucket)
            if force:
                shutil.rmtree(p)
            else:
                if any(os.scandir(p)):
                    raise errors.VolumeNotEmpty(bucket)
                os.rmdir(p)
        await self._run("delete_vol", _rm)

    # ----------------------------------------------------------------- metadata
    async def read_meta(self, bucket: str, key: str) -> bytes:
        return await self.read_all(bucket, os.path.join(key, META_FILE))

    async def write_meta(self, bucket: str, key: str, data: bytes) -> None:
        await self.write_all(bucket, os.path.join(key, META_FILE), data)

    async def read_all(self, bucket: str, path: str) -> bytes:
        def _read():
            full = self._p(bucket, path)  # path check first
            if not os.path.isdir(self._p(bucket)):
                raise errors.VolumeNotFound(bucket)
            try:
                with open(full, "rb") as f:
                    return f.read()
            except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
                raise errors.FileNotFound(f"{bucket}/{path}")
        return await self._run("read_all", _read)

    async def write_all(self, bucket: str, path: str, data: bytes) -> None:
        await self._run("write_all", _write_atomic, self._p(bucket, path), bytes(data))

    # -------------------------------------------------------------- shard files
    async def create_file(self, bucket: str, path: str, size: int,
                          chunks: AsyncIterator[bytes]) -> int:
        """chunks yields shard blocks; we write [hash][block] pairs, then fsync.
        size is the expected shard-data size, or -1 when unknown."""
        full = self._p(bucket, path)
        await self._run("mkdir", lambda: os.makedirs(os.path.dirname(full), exist_ok=True))
        f = await self._run("open", open, full, "wb")
        written = 0
        try:
            async for block in chunks:
                h = hash32(block)
                await self._run("write", f.write, h + bytes(block))
                written += len(block)
            if size >= 0 and written != size:
                raise OSError(f"short write {written} != {size}")
            await self._run("fsync", lambda: (f.flush(), os.fsync(f.fileno())))
        finally:
            f.close()
        return written

    async def read_file(self, bucket: str, path: str, offset: int, length: int,
                        shard_size: int) -> bytes:
        """Read `length` bytes of shard data starting at `offset` (a multiple of
        shard_size), verifying each block's BLAKE3 hash."""
        def _read():
            full = self._p(bucket, path)
            try:
                f = open(full, "rb")
            except (FileNotFoundError, NotADirectoryError):
                raise errors.FileNotFound(f"{bucket}/{path}")
            with f:
                block_idx = offset // shard_size
                f.seek(block_idx * (HASH_LEN + shard_size))
                out = bytearray()
                remaining = length
                while remaining > 0:
                    h = f.read(HASH_LEN)
                    want = min(shard_size, remaining)
                    block = f.read(want)
                    if len(h) < HASH_LEN or len(block) < want:
                        raise errors.FileCorrupt(f"{bucket}/{path}: truncated")
                    if hash32(block) != h:
                        metrics.BITROT_DETECTED.labels(self.endpoint).inc()
                        raise errors.FileCorrupt(f"{bucket}/{path}: bitrot at block {block_idx}")
                    out += block
                    remaining -= want
                    block_idx += 1
                return bytes(out)
        return await self._run("read_file", _read)

    async def verify_file(self, bucket: str, path: str, shard_size: int, file_size: int) -> bool:
        """Full bitrot scan of a shard file."""
        if file_size == 0:
            return True
        try:
            data = await self.read_file(bucket, path, 0, file_size, shard_size)
        except (errors.FileCorrupt, errors.FileNotFound):
            return False
        return len(data) == file_size

    async def rename_data(self, src_bucket: str, src_path: str, meta: bytes,
                          dst_bucket: str, dst_key: str) -> None:
        """Atomically install a new version: move the data dir + replace xl.meta.
        src_path is the data dir inside tmp (it may not exist for inline objects)."""
        def _do():
            if not os.path.isdir(self._p(dst_bucket)):
                raise errors.VolumeNotFound(dst_bucket)
            src = self._p(src_bucket, src_path) if src_path else ""
            dst_dir = self._p(dst_bucket, dst_key)
            os.makedirs(dst_dir, exist_ok=True)
            if src and os.path.isdir(src):
                target = os.path.join(dst_dir, os.path.basename(src))
                if not os.path.exists(target):
                    os.replace(src, target)
                else:  # merge (multipart parts, heals of a partially present dir)
                    for name in os.listdir(src):
                        os.replace(os.path.join(src, name), os.path.join(target, name))
                    shutil.rmtree(src, ignore_errors=True)
                _fsync_dir(dst_dir)
            if meta:  # empty meta = move data only
                _write_atomic(os.path.join(dst_dir, META_FILE), meta)
            if src:
                parent = os.path.dirname(src)
                if os.path.basename(os.path.dirname(parent)) == "tmp":
                    shutil.rmtree(parent, ignore_errors=True)
        await self._run("rename_data", _do)

    async def delete(self, bucket: str, path: str, recursive: bool = False) -> None:
        def _rm():
            full = self._p(bucket, path)
            if not os.path.exists(full):
                raise errors.FileNotFound(f"{bucket}/{path}")
            if os.path.isdir(full):
                if recursive:
                    shutil.rmtree(full)
                else:
                    os.rmdir(full)
            else:
                os.remove(full)
            # remove now-empty parent directories up to the bucket
            parent = os.path.dirname(full)
            vol = self._p(bucket)
            while parent != vol and parent.startswith(vol):
                try:
                    os.rmdir(parent)
                except OSError:
                    break
                parent = os.path.dirname(parent)
        await self._run("delete", _rm)

    async def list_dir(self, bucket: str, path: str) -> list[str]:
        def _ls():
            try:
                return sorted(os.listdir(self._p(bucket, path)))
            except (FileNotFoundError, NotADirectoryError):
                raise errors.FileNotFound(f"{bucket}/{path}")
        return await self._run("list_dir", _ls)

    # -------------------------------------------------------------------- walk
    def _walk_sync(self, bucket: str, prefix: str) -> list[tuple[str, bytes]]:
        vol = self._p(bucket)
        if not os.path.isdir(vol):
            raise errors.VolumeNotFound(bucket)
        out: list[tuple[str, bytes]] = []
        start_rel = prefix.rsplit("/", 1)[0] if "/" in prefix else ""

        def visit(rel: str) -> None:
            d = os.path.join(vol, rel) if rel else vol
            try:
                entries = sorted(os.listdir(d))
            except (FileNotFoundError, NotADirectoryError):
                return
            if META_FILE in entries and rel:
                try:
                    with open(os.path.join(d, META_FILE), "rb") as f:
                        if rel.startswith(prefix):
                            out.append((rel.replace(os.sep, "/"), f.read()))
                except OSError:
                    pass
            for name in entries:
                if name == META_FILE or name.endswith(".tmp"):
                    continue
                if not rel and bucket == SYS_VOL and name in _SYS_SKIP | {"format.json"}:
                    continue
                if META_FILE in entries and _UUID_RE.match(name):
                    continue  # a data dir, not a nested key
                child = f"{rel}/{name}" if rel else name
                if not os.path.isdir(os.path.join(d, name)):
                    continue
                # prune subtrees that can't match the prefix
                if prefix and not (child.startswith(prefix) or prefix.startswith(child + "/")
                                   or prefix.startswith(child)):
                    continue
                visit(child)

        visit(start_rel)
        out.sort(key=lambda kv: kv[0])
        return out

    async def walk_dir(self, bucket: str, prefix: str = "") -> AsyncIterator[tuple[str, bytes]]:
        for item in await self._run("walk_dir", self._walk_sync, bucket, prefix):
            yield item

    async def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
