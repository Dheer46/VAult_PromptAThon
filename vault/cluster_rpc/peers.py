"""Broadcasts to every other node (cache invalidation, stats collection)."""
from __future__ import annotations

import asyncio

from ..observability.log import log
from .remote_disk import PeerClient


class Peers:
    def __init__(self, clients: list[PeerClient]):
        self.clients = clients

    async def notify_all(self, kind: str, payload: bytes = b"") -> None:
        res = await asyncio.gather(*[c.notify(kind, payload) for c in self.clients],
                                   return_exceptions=True)
        for c, r in zip(self.clients, res):
            if isinstance(r, BaseException):
                log.debug("peer notify failed", peer=c.node, kind=kind, error=str(r))

    async def server_infos(self) -> list[dict]:
        res = await asyncio.gather(*[c.server_info() for c in self.clients], return_exceptions=True)
        return [r if isinstance(r, dict) else {"node": c.node, "state": "offline", "error": str(r)}
                for c, r in zip(self.clients, res)]

    async def replication_stats(self) -> list[dict]:
        res = await asyncio.gather(*[c.replication_stats() for c in self.clients],
                                   return_exceptions=True)
        return [r for r in res if isinstance(r, dict)]
