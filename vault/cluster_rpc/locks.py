"""Distributed locks: a majority (N/2+1) of nodes must grant a lock.

Each node runs a LockTable (served over the Lock gRPC service). DistributedLock
asks every node's locker, keeps the lock only if a majority granted it, and
refreshes it every TTL/3 so a crashed holder doesn't block the key forever.
A node on the minority side of a partition can't get a majority, so it can't write.
"""
from __future__ import annotations

import asyncio
import random
import time
import uuid
from dataclasses import dataclass, field

from ..errors import LockLost, S3Error
from ..observability import metrics


@dataclass
class _Entry:
    writer: str | None = None
    readers: dict[str, float] = field(default_factory=dict)  # uid -> expiry
    expiry: float = 0.0


class LockTable:
    """The local lock table on one node."""

    def __init__(self):
        self._locks: dict[str, _Entry] = {}
        self._cleanup_task: asyncio.Task | None = None

    def _gc(self, resource: str) -> _Entry | None:
        e = self._locks.get(resource)
        if e is None:
            return None
        now = time.monotonic()
        if e.writer and e.expiry < now:
            e.writer = None
        e.readers = {u: x for u, x in e.readers.items() if x >= now}
        if not e.writer and not e.readers:
            del self._locks[resource]
            return None
        return e

    def lock(self, resource: str, uid: str, ttl_ms: int, read: bool) -> bool:
        e = self._gc(resource)
        exp = time.monotonic() + ttl_ms / 1000
        if read:
            if e and e.writer:
                return False
            e = e or self._locks.setdefault(resource, _Entry())
            e.readers[uid] = exp
            return True
        if e is not None:
            return e.writer == uid  # re-entrant for the same uid
        self._locks[resource] = _Entry(writer=uid, expiry=exp)
        return True

    def unlock(self, resource: str, uid: str) -> bool:
        e = self._gc(resource)
        if e is None:
            return False
        if e.writer == uid:
            e.writer = None
        elif uid in e.readers:
            del e.readers[uid]
        else:
            return False
        self._gc(resource)
        return True

    def refresh(self, resource: str, uid: str, ttl_ms: int) -> bool:
        e = self._gc(resource)
        if e is None:
            return False
        exp = time.monotonic() + ttl_ms / 1000
        if e.writer == uid:
            e.expiry = exp
            return True
        if uid in e.readers:
            e.readers[uid] = exp
            return True
        return False

    def force_unlock(self, resource: str) -> bool:
        return self._locks.pop(resource, None) is not None

    def snapshot(self) -> dict:
        return {r: {"writer": e.writer, "readers": len(e.readers)} for r, e in self._locks.items()
                if self._gc(r)}

    async def cleanup_loop(self, interval: float = 5.0) -> None:
        while True:
            await asyncio.sleep(interval)
            for r in list(self._locks):
                self._gc(r)


class LocalLocker:
    """Locker for this node's own table (no network)."""

    def __init__(self, table: LockTable, name: str = "local"):
        self.table = table
        self.name = name

    async def lock(self, resource, uid, owner, ttl_ms, read):
        return self.table.lock(resource, uid, ttl_ms, read)

    async def unlock(self, resource, uid, owner="", read=False):
        return self.table.unlock(resource, uid)

    async def refresh(self, resource, uid, owner, ttl_ms, read=False):
        return self.table.refresh(resource, uid, ttl_ms)

    async def force_unlock(self, resource):
        return self.table.force_unlock(resource)


class DistributedLock:
    def __init__(self, lockers: list, resource: str, owner: str = ""):
        self.lockers = lockers
        self.resource = resource
        self.owner = owner
        self.uid = str(uuid.uuid4())
        self.quorum = len(lockers) // 2 + 1
        self.read = False
        self.lost = False
        self._granted: list = []
        self._refresh: asyncio.Task | None = None

    async def acquire(self, read: bool = False, timeout: float = 10.0, ttl_ms: int = 30_000):
        self.read = read
        t0 = time.monotonic()
        deadline = t0 + timeout
        backoff = 0.01
        while True:
            results = await asyncio.gather(
                *[asyncio.wait_for(l.lock(self.resource, self.uid, self.owner, ttl_ms, read), 5)
                  for l in self.lockers], return_exceptions=True)
            granted = [l for l, r in zip(self.lockers, results) if r is True]
            if len(granted) >= self.quorum:
                self._granted = granted
                self._refresh = asyncio.create_task(self._refresh_loop(ttl_ms))
                metrics.LOCK_WAIT.observe(time.monotonic() - t0)
                return self
            await asyncio.gather(*[l.unlock(self.resource, self.uid, self.owner, read)
                                   for l in granted], return_exceptions=True)  # release partial locks
            if time.monotonic() + backoff > deadline:
                break
            await asyncio.sleep(backoff * (0.5 + random.random()))  # jitter avoids livelock
            backoff = min(backoff * 2, 0.5)
        raise S3Error("SlowDown", f"could not lock {self.resource}", 503)

    async def _refresh_loop(self, ttl_ms: int) -> None:
        while True:
            await asyncio.sleep(ttl_ms / 3000)
            results = await asyncio.gather(
                *[l.refresh(self.resource, self.uid, self.owner, ttl_ms, self.read)
                  for l in self.lockers], return_exceptions=True)
            if sum(r is True for r in results) < self.quorum:
                # We lost the lock (partition). The caller must abort the operation.
                self.lost = True
                return

    def check(self) -> None:
        if self.lost:
            raise LockLost(self.resource)

    async def release(self) -> None:
        if self._refresh:
            self._refresh.cancel()
        await asyncio.gather(*[l.unlock(self.resource, self.uid, self.owner, self.read)
                               for l in self.lockers], return_exceptions=True)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.release()


class NSLock:
    """Convenience factory: `async with ns.write(bucket, key): ...`"""

    def __init__(self, lockers: list, owner: str = ""):
        self.lockers = lockers
        self.owner = owner

    def _make(self, resource: str) -> DistributedLock:
        return DistributedLock(self.lockers, resource, self.owner)

    async def write(self, resource: str, timeout: float = 10.0) -> DistributedLock:
        return await self._make(resource).acquire(read=False, timeout=timeout)

    async def read(self, resource: str, timeout: float = 10.0) -> DistributedLock:
        return await self._make(resource).acquire(read=True, timeout=timeout)
