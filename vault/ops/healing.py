"""Healing Service (diagram box).

Arrow #9: Healing -> Disk Storage "checks disks" (disk_info every 10 s).
Arrow #10: Healing -> Storage Facade "repairs storage" (StorageFacade.heal_object).

Three kinds of healing:
  object  - MRF queue (in the Storage Facade), read errors, scanner findings
  bucket  - a drive misses a bucket directory
  drive   - a blank drive appears in a slot (replacement) or a drive returns after
            a long outage: every object of that drive's erasure set is healed.
Drive heals are resumable (.vault.sys/.healing.bin on the drive being healed),
throttled, and run behind MRF/read-error heals in priority.
"""
from __future__ import annotations

import asyncio
import time

import msgpack

from .. import errors
from ..observability import metrics
from ..observability.log import log
from ..storage_core.format import write_format
from ..storage_core.storage_api import SYS_VOL

MONITOR_INTERVAL = 10.0
AWAY_THRESHOLD = 60.0
HEAL_CONCURRENCY = 4
TRACKER = ".healing.bin"


class HealingService:
    def __init__(self, storage, bucket_meta, layout: dict | None = None):
        self.storage = storage  # StorageFacade (arrow #10 target)
        self.bucket_meta = bucket_meta
        self.layout = layout
        self.queue: asyncio.Queue = asyncio.Queue(100_000)  # scanner findings, deep heals
        self._pending: set = set()
        self._offline_since: dict[str, float] = {}
        self._drive_heals: dict[str, asyncio.Task] = {}
        self.status: dict[str, dict] = {}  # endpoint -> progress
        self.recent: list[dict] = []

    # ------------------------------------------------------------ object heals
    def queue_heal(self, bucket: str, key: str, deep: bool = False, kind: str = "scanner") -> None:
        item = (bucket, key, deep, kind)
        if (bucket, key) in self._pending:
            return
        try:
            self.queue.put_nowait(item)
            self._pending.add((bucket, key))
        except asyncio.QueueFull:
            pass

    async def worker(self) -> None:
        while True:
            bucket, key, deep, kind = await self.queue.get()
            self._pending.discard((bucket, key))
            try:
                res = await self.storage.heal_object(bucket, key, deep=deep, kind=kind)  # arrow #10
                if res.get("healed") or res.get("dangling_removed"):
                    self.recent = (self.recent + [{**res, "time": time.time()}])[-100:]
            except Exception as e:
                log.debug("heal failed", bucket=bucket, key=key, error=str(e))

    # ------------------------------------------------------ disks (arrow #9)
    def local_drives(self):
        for s in self.storage.pools.all_sets:
            for pos, d in enumerate(s.drives):
                if d is not None and d.is_local:
                    yield s, pos, d

    async def monitor_drives(self) -> None:
        while True:
            try:
                await self.check_drives_once()
            except Exception as e:
                log.warning("drive monitor failed", error=str(e))
            await asyncio.sleep(MONITOR_INTERVAL)

    async def check_drives_once(self) -> list[asyncio.Task]:
        started = []
        for s, pos, d in list(self.local_drives()):
            try:
                info = await d.disk_info()  # arrow #9 "checks disks"
            except Exception:
                self._offline_since.setdefault(d.endpoint, time.time())
                continue
            if not info.get("formatted") and self.layout:
                slot = self._slot(s, pos)
                await write_format(d, self.layout, slot)  # replaced drive
                log.info("blank drive detected; formatted into its slot", endpoint=d.endpoint)
                started.append(self.start_drive_heal(s, pos, d, reason="replaced"))
            elif d.endpoint in self._offline_since:
                away = time.time() - self._offline_since.pop(d.endpoint)
                if away >= AWAY_THRESHOLD:  # was away: may have missed writes
                    started.append(self.start_drive_heal(s, pos, d, reason=f"offline {away:.0f}s"))
            elif not d.healing and self._has_tracker(d):
                started.append(self.start_drive_heal(s, pos, d, reason="resume"))
        return [t for t in started if t is not None]

    def _slot(self, s, pos: int) -> int:
        offset = 0
        for other in self.storage.pools.all_sets:
            if other is s:
                return offset + pos
            offset += other.n
        return pos

    def _has_tracker(self, d) -> bool:
        import os
        return os.path.exists(os.path.join(getattr(d, "root", ""), SYS_VOL, TRACKER))

    # ------------------------------------------------------------- drive heal
    def start_drive_heal(self, s, pos: int, d, reason: str = "") -> asyncio.Task:
        t = self._drive_heals.get(d.endpoint)
        if t and not t.done():
            return t
        log.info("drive heal started", endpoint=d.endpoint, set=s.index, reason=reason)
        t = self._drive_heals[d.endpoint] = asyncio.create_task(self._heal_drive(s, pos, d))
        return t

    async def _heal_drive(self, s, pos: int, d) -> None:
        d.healing = True
        started = time.time()
        try:
            try:
                tracker = msgpack.unpackb(await d.read_all(SYS_VOL, TRACKER))
            except errors.StorageError:
                tracker = {"bucket": "", "key": "", "healed": 0, "started": started}
            buckets = [SYS_VOL] + sorted(b["name"] for b in await self.storage.list_buckets())
            for b in buckets:
                await self.storage.heal_bucket(b)
            entries: list[tuple[str, str]] = []
            for b in buckets:
                try:
                    for key, _ in await s.list_entries(b):
                        entries.append((b, key))
                except errors.S3Error:
                    continue
            total = len(entries) or 1
            resume = (tracker.get("bucket", ""), tracker.get("key", ""))
            todo = [e for e in entries if e > resume] if resume != ("", "") else entries
            done = total - len(todo)
            sem = asyncio.Semaphore(HEAL_CONCURRENCY)
            last_saved = time.time()

            async def heal_one(b, k):
                async with sem:
                    try:
                        await self.storage.heal_object(b, k, kind="drive")  # arrow #10
                    except Exception as e:
                        log.debug("drive heal object failed", bucket=b, key=k, error=str(e))

            for i in range(0, len(todo), HEAL_CONCURRENCY * 4):
                batch = todo[i:i + HEAL_CONCURRENCY * 4]
                await asyncio.gather(*[heal_one(b, k) for b, k in batch])
                done += len(batch)
                ratio = done / total
                metrics.HEAL_DRIVE_PROGRESS.labels(d.endpoint).set(ratio)
                self.status[d.endpoint] = {"progress": ratio, "objects": done, "total": total,
                                           "started": started, "state": "healing"}
                if time.time() - last_saved > 2:
                    tracker.update(bucket=batch[-1][0], key=batch[-1][1], healed=done)
                    await d.write_all(SYS_VOL, TRACKER, msgpack.packb(tracker))
                    last_saved = time.time()
            try:
                await d.delete(SYS_VOL, TRACKER)
            except errors.StorageError:
                pass
            metrics.HEAL_DRIVE_PROGRESS.labels(d.endpoint).set(1.0)
            self.status[d.endpoint] = {"progress": 1.0, "objects": total, "total": total,
                                       "started": started, "finished": time.time(), "state": "done"}
            log.info("drive heal finished", endpoint=d.endpoint, objects=total,
                     seconds=round(time.time() - started, 1))
        except Exception as e:
            self.status[d.endpoint] = {"state": "failed", "error": str(e)}
            log.warning("drive heal failed", endpoint=d.endpoint, error=str(e))
        finally:
            d.healing = False

    async def heal_prefix(self, bucket: str, prefix: str = "", deep: bool = False) -> dict:
        """Admin-triggered heal: POST /vault/admin/v1/heal/{bucket}/{prefix}."""
        await self.storage.heal_bucket(bucket)
        res = await self.storage.list_objects(bucket, prefix=prefix, max_keys=10_000_000)
        healed = 0
        for oi in res.objects:
            r = await self.storage.heal_object(bucket, oi.key, deep=deep, kind="admin")
            healed += bool(r.get("healed"))
        return {"bucket": bucket, "prefix": prefix, "scanned": len(res.objects), "healed": healed}

    def info(self) -> dict:
        return {"queue": self.queue.qsize(), "mrf": self.storage.mrf.qsize(),
                "drives": self.status, "recent": self.recent[-20:]}
