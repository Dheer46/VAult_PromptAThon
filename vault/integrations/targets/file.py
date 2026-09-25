"""File target: append JSON lines, rotate by size (used for audit)."""
from __future__ import annotations

import asyncio
import json
import os
import time

from .base import Target


class FileTarget(Target):
    kind = "file"

    def __init__(self, name: str, path: str, queue_dir: str, max_bytes: int = 100 * 1024 * 1024, **_):
        super().__init__(name, queue_dir)
        self.path = path
        self.max_bytes = max_bytes
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def _write(self, batch: list[dict]) -> None:
        try:
            if os.path.getsize(self.path) > self.max_bytes:
                os.replace(self.path, f"{self.path}.{int(time.time())}")
        except FileNotFoundError:
            pass
        with open(self.path, "a", encoding="utf-8") as f:
            for e in batch:
                f.write(json.dumps(e, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())

    async def send(self, batch: list[dict]) -> None:
        await asyncio.to_thread(self._write, batch)
