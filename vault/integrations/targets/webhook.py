"""Webhook target: POST JSON (one request per entry, like MinIO) with an optional
auth token header."""
from __future__ import annotations

import httpx

from .base import Target


class WebhookTarget(Target):
    kind = "webhook"

    def __init__(self, name: str, url: str, queue_dir: str, auth_token: str = "", **_):
        super().__init__(name, queue_dir)
        self.url = url
        headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
        self._http = httpx.AsyncClient(timeout=5.0, headers=headers)

    async def send(self, batch: list[dict]) -> None:
        for entry in batch:
            r = await self._http.post(self.url, json=entry)
            r.raise_for_status()

    async def is_online(self) -> bool:
        try:
            await self._http.head(self.url)
            return True
        except httpx.HTTPError:
            return False
