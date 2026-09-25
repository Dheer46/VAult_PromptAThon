"""Scanner Service (diagram box): continuously walks all data to find problems and
feeds the Healing Service, the Lifecycle Engine and Bucket Replication, while
keeping per-bucket usage statistics.

One loop per node, only over its own local drives. Progress is stored in
`.vault.sys/scanner/<node>.bin` so a restart resumes the cycle count. After each
object the scanner sleeps in proportion to the time it took (default ~10% of
disk time) and backs off entirely while the API is busy.
"""
from __future__ import annotations

import asyncio
import json
import time

import msgpack

from .. import errors
from ..observability import metrics
from ..observability.log import log
from ..storage_core.erasure import ErasureCoder
from ..storage_core.filemeta import REPL_STATUS, FileMeta
from ..storage_core.storage_api import SYS_VOL

SIZE_BUCKETS = [1024, 64 * 1024, 1 << 20, 16 << 20, 128 << 20, 1 << 30]
REQUEUE_AFTER = 600  # seconds a PENDING replication may sit before the scanner re-queues it


class ActivityGauge:
    """In-flight API requests; the scanner pauses when the node is busy."""
    in_flight = 0


class ScannerService:
    def __init__(self, settings, storage, bucket_meta, healing, lifecycle, replication, node: str):
        self.s = settings
        self.storage = storage
        self.bucket_meta = bucket_meta
        self.healing = healing
        self.lifecycle = lifecycle
        self.replication = replication
        self.node = node
        self.cycle = 0
        self.usage: dict[str, dict] = {}
        self.last_cycle: dict = {}

    def _local(self):
        for s in self.storage.pools.all_sets:
            for pos, d in enumerate(s.drives):
                if d is not None and d.is_local:
                    yield s, pos, d

    @staticmethod
    def _is_leader(s, pos: int) -> bool:
        """Only one drive acts per object: the lowest online position in its set."""
        for i, d in enumerate(s.drives):
            if d is not None and not getattr(d, "faulty", False) and getattr(d, "online", True):
                return i == pos
        return False

    async def _state_drive(self):
        for _, _, d in self._local():
            return d
        return None

    async def _load_state(self) -> None:
        d = await self._state_drive()
        if d is None:
            return
        try:
            st = msgpack.unpackb(await d.read_all(SYS_VOL, f"scanner/{self.node}.bin"))
            self.cycle = st.get("cycle", 0)
        except errors.StorageError:
            pass

    async def _save_state(self) -> None:
        d = await self._state_drive()
        if d is None:
            return
        await d.write_all(SYS_VOL, f"scanner/{self.node}.bin",
                          msgpack.packb({"cycle": self.cycle, "time": time.time()}))
        await d.write_all(SYS_VOL, f"scanner/usage-{self.node}.json",
                          json.dumps({"time": time.time(), "cycle": self.cycle,
                                      "buckets": self.usage}).encode())

    async def _throttle(self, took: float) -> None:
        speed = max(0.01, min(1.0, self.s.scanner_speed))
        await asyncio.sleep(took * (1 / speed - 1))
        while ActivityGauge.in_flight > 32:  # pause when the API is busy
            await asyncio.sleep(0.5)

    async def run(self) -> None:
        await self._load_state()
        await asyncio.sleep(5)
        while True:
            t0 = time.time()
            try:
                await self.scan_cycle()
            except Exception as e:
                log.warning("scanner cycle failed", error=str(e))
            self.last_cycle = {"cycle": self.cycle, "seconds": round(time.time() - t0, 2),
                               "finished": time.time()}
            await asyncio.sleep(self.s.scanner_cycle_pause)

    async def scan_cycle(self) -> None:
        self.cycle += 1
        metrics.SCANNER_CYCLE.set(self.cycle)
        deep = self.s.scanner_deep_every > 0 and self.cycle % self.s.scanner_deep_every == 0
        heal_check = self.s.scanner_heal_every > 0 and self.cycle % self.s.scanner_heal_every == 0
        usage: dict[str, dict] = {}
        for s, pos, d in list(self._local()):
            if getattr(d, "faulty", False) or getattr(d, "healing", False):
                continue
            leader = self._is_leader(s, pos)
            try:
                buckets = await d.list_vols()
            except errors.StorageError:
                continue
            for bucket in buckets:
                try:
                    bm = await self.bucket_meta.get(bucket)
                except errors.S3Error:
                    continue
                u = usage.setdefault(bucket, {"objects": 0, "versions": 0, "delete_markers": 0,
                                              "bytes": 0, "histogram": [0] * (len(SIZE_BUCKETS) + 1),
                                              "replication_pending": 0, "replication_failed": 0})
                try:
                    entries = [e async for e in d.walk_dir(bucket)]
                except errors.StorageError:
                    continue
                for key, raw in entries:
                    t = time.time()
                    await self.scan_object(s, pos, d, bm, key, raw, leader, deep, heal_check, u)
                    metrics.SCANNER_OBJECTS.inc()
                    await self._throttle(time.time() - t)
                if leader and s is self.storage.pools.all_sets[0] and self.lifecycle:
                    try:
                        await self.lifecycle.abort_stale_uploads(bm)
                    except Exception as e:
                        log.debug("abort stale uploads failed", bucket=bucket, error=str(e))
        self.usage = usage
        try:
            await self._save_state()
        except errors.StorageError:
            pass
        log.info("scanner cycle done", cycle=self.cycle, deep=deep, buckets=len(usage))

    async def scan_object(self, s, pos, d, bm, key: str, raw: bytes, leader: bool, deep: bool,
                          heal_check: bool, u: dict) -> None:
        bucket = bm.name
        try:
            fm = FileMeta.unmarshal(raw)
        except errors.FileCorrupt:
            self.healing.queue_heal(bucket, key, kind="scanner")  # corrupt -> heal
            return
        # 1. deep scan: every drive verifies its own shard files (bitrot)
        if deep:
            for v in fm.versions:
                if v.is_delete_marker or not v.data_dir or not v.erasure:
                    continue
                coder = ErasureCoder(v.erasure.k, v.erasure.m, v.erasure.block_size)
                for p in v.parts:
                    ok = await d.verify_file(bucket, f"{key}/{v.data_dir}/part.{p.number}",
                                             coder.shard_size(v.erasure.block_size),
                                             coder.shard_file_size(p.size))
                    if not ok:
                        log.warning("deep scan found corrupt shard", bucket=bucket, key=key,
                                    endpoint=d.endpoint)
                        self.healing.queue_heal(bucket, key, deep=True, kind="scanner")
                        break
        if not leader:
            return
        # usage stats (leader copy only, so each object is counted once)
        latest = fm.latest()
        u["versions"] += sum(not v.is_delete_marker for v in fm.versions)
        u["delete_markers"] += sum(v.is_delete_marker for v in fm.versions)
        if latest and not latest.is_delete_marker:
            u["objects"] += 1
            size = int(latest.meta_sys.get("x-vault-actual-size", latest.parts[0].actual_size
                                           if latest.parts else latest.size))
            u["bytes"] += size
            u["histogram"][next((i for i, b in enumerate(SIZE_BUCKETS) if size < b), len(SIZE_BUCKETS))] += 1
        # 2. heal check (sampled): compare this object across the set
        if heal_check:
            self.healing.queue_heal(bucket, key, kind="scanner")
        # 3. lifecycle: expired or due for transition?
        if self.lifecycle:
            actions = self.lifecycle.evaluate(bm, key, fm)
            if actions:
                await self.lifecycle.apply(bm, key, actions)
        # 4. replication: pending or failed past retry time -> requeue
        if self.replication:
            queued = {(t["bucket"], t["key"], t["version_id"]) for t in self.replication._queued.values()}
            for v in fm.versions:
                st = v.meta_sys.get(REPL_STATUS)
                if st == "PENDING":
                    u["replication_pending"] += 1
                elif st == "FAILED":
                    u["replication_failed"] += 1
                if st in ("PENDING", "FAILED") and (bucket, key, v.version_id) not in queued \
                        and time.time() - v.mod_time_ns / 1e9 > REQUEUE_AFTER:
                    v.meta_sys.pop(REPL_STATUS, None)
                    await self.replication.evaluate(bucket, key, v, op="put")

    def info(self) -> dict:
        return {"cycle": self.cycle, "last": self.last_cycle, "usage": self.usage}
