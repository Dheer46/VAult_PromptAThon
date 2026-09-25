"""Durable queue store: an append-only directory of small JSON files, one per
entry, written before delivery and deleted after success. Reloaded on startup.
Shared by event targets, audit targets, replication and the tier journal
(this is the "pipeline" code both Event Notifications and Audit Pipeline use)."""
from __future__ import annotations

import json
import os
import time
import uuid


class QueueStore:
    def __init__(self, directory: str, limit: int = 100_000):
        self.dir = directory
        self.limit = limit
        os.makedirs(directory, exist_ok=True)
        self._count = len(self._names())

    def _names(self) -> list[str]:
        try:
            return sorted(n for n in os.listdir(self.dir) if n.endswith(".json"))
        except FileNotFoundError:
            return []

    def __len__(self) -> int:
        return self._count

    def put(self, entry: dict) -> tuple[str, bool]:
        """Persist an entry. Returns (name, dropped_oldest)."""
        dropped = False
        if self._count >= self.limit:
            names = self._names()
            if names:
                self.delete(names[0])
                dropped = True
        name = f"{time.time_ns():020d}-{uuid.uuid4().hex[:8]}.json"
        tmp = os.path.join(self.dir, name + ".tmp")
        with open(tmp, "w") as f:
            json.dump(entry, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, os.path.join(self.dir, name))
        self._count += 1
        return name, dropped

    def get(self, name: str) -> dict | None:
        try:
            with open(os.path.join(self.dir, name)) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def update(self, name: str, entry: dict) -> None:
        tmp = os.path.join(self.dir, name + ".tmp")
        with open(tmp, "w") as f:
            json.dump(entry, f)
        os.replace(tmp, os.path.join(self.dir, name))

    def delete(self, name: str) -> None:
        try:
            os.remove(os.path.join(self.dir, name))
            self._count = max(0, self._count - 1)
        except FileNotFoundError:
            pass

    def list(self, limit: int | None = None) -> list[str]:
        names = self._names()
        self._count = len(names)
        return names[:limit] if limit else names

    def oldest_age(self) -> float:
        names = self._names()
        if not names:
            return 0.0
        return max(0.0, time.time() - int(names[0].split("-")[0]) / 1e9)
