"""Target = one destination for events or audit entries.

producer -> bounded in-memory queue -> durable queue store -> per-target sender
with exponential backoff while the target is offline. The store is capped;
when full the oldest entry is dropped and vault_events_dropped_total increments.
"""
from __future__ import annotations

import asyncio
import os
from abc import ABC, abstractmethod

from ...observability import metrics
from ...observability.log import log
from ..queue_store import QueueStore

BATCH = 50


class Target(ABC):
    kind = "base"

    def __init__(self, name: str, queue_dir: str, limit: int = 100_000):
        self.name = name
        self.id = f"{self.kind}:{name}"
        self.store = QueueStore(os.path.join(queue_dir, self.id.replace(":", "_")), limit)
        self._wake = asyncio.Event()
        self._task: asyncio.Task | None = None
        self.online = True

    @abstractmethod
    async def send(self, batch: list[dict]) -> None: ...

    async def is_online(self) -> bool:
        return True

    def enqueue(self, entry: dict) -> None:
        """Never blocks the S3 request: persist and return."""
        _, dropped = self.store.put(entry)
        if dropped:
            metrics.EVENTS_DROPPED.labels(self.id).inc()
        metrics.EVENTS_QUEUED.labels(self.id).set(len(self.store))
        self._wake.set()

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        backoff = 0.5
        while True:
            names = self.store.list(BATCH)
            if not names:
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), 5)
                except asyncio.TimeoutError:
                    pass
                continue
            entries = [(n, self.store.get(n)) for n in names]
            batch = [e for _, e in entries if e is not None]
            try:
                if batch:
                    await self.send(batch)
                for n, _ in entries:
                    self.store.delete(n)
                metrics.EVENTS_SENT.labels(self.id).inc(len(batch))
                metrics.EVENTS_QUEUED.labels(self.id).set(len(self.store))
                if not self.online:
                    log.info("target back online", target=self.id)
                self.online = True
                backoff = 0.5
            except Exception as e:
                if self.online:
                    log.warning("target offline, queueing", target=self.id, error=str(e))
                self.online = False
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)

    async def close(self) -> None:
        if self._task:
            self._task.cancel()

    def info(self) -> dict:
        return {"id": self.id, "online": self.online, "queued": len(self.store)}
