"""Kafka target (aiokafka producer; one topic per target). Works with Redpanda."""
from __future__ import annotations

import json

from .base import Target


class KafkaTarget(Target):
    kind = "kafka"

    def __init__(self, name: str, brokers: str, topic: str, queue_dir: str, **_):
        super().__init__(name, queue_dir)
        self.brokers = brokers
        self.topic = topic
        self._producer = None

    async def _get(self):
        if self._producer is None:
            from aiokafka import AIOKafkaProducer
            p = AIOKafkaProducer(bootstrap_servers=self.brokers, request_timeout_ms=5000,
                                 value_serializer=lambda v: json.dumps(v).encode())
            await p.start()
            self._producer = p
        return self._producer

    async def send(self, batch: list[dict]) -> None:
        try:
            p = await self._get()
            for entry in batch:
                key = (entry.get("Key") or entry.get("requestID") or "").encode() or None
                await p.send_and_wait(self.topic, entry, key=key)
        except Exception:
            if self._producer is not None:
                try:
                    await self._producer.stop()
                except Exception:
                    pass
                self._producer = None
            raise

    async def close(self) -> None:
        await super().close()
        if self._producer:
            await self._producer.stop()
