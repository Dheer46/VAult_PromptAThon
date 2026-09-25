"""Pools of erasure sets. An object lives entirely inside one erasure set; the set
is chosen by a keyed hash of the object name (keyed with the deployment id so
nobody can craft names that pile onto one set)."""
from __future__ import annotations

import asyncio
import hashlib
import uuid

from .. import errors
from .erasure_set import ErasureSet


def set_index(object_name: str, deployment_id: str, set_count: int) -> int:
    key = uuid.UUID(deployment_id).bytes
    h = hashlib.blake2b(object_name.encode(), key=key, digest_size=8).digest()
    return int.from_bytes(h, "big") % set_count


class ServerPool:
    def __init__(self, index: int, sets: list[ErasureSet], deployment_id: str):
        self.index = index
        self.sets = sets
        self.deployment_id = deployment_id

    def set_for(self, key: str) -> ErasureSet:
        return self.sets[set_index(key, self.deployment_id, len(self.sets))]

    async def free_bytes(self) -> int:
        total = 0
        for s in self.sets:
            res = await s._each(lambda d: d.disk_info())
            total += sum(r["free"] for r in res if isinstance(r, dict))
        return total


class ServerPools:
    def __init__(self, pools: list[ServerPool]):
        self.pools = pools

    @property
    def all_sets(self) -> list[ErasureSet]:
        return [s for p in self.pools for s in p.sets]

    async def set_for_existing(self, bucket: str, key: str) -> ErasureSet:
        """The set holding bucket/key; for a single pool that's just the hash."""
        if len(self.pools) == 1:
            return self.pools[0].set_for(key)
        for p in self.pools:
            s = p.set_for(key)
            try:
                await s.get_object_info(bucket, key)
                return s
            except errors.S3Error as e:
                if e.code not in ("NoSuchKey", "NoSuchVersion"):
                    raise
        return self.pools[0].set_for(key)

    async def set_for_new(self, bucket: str, key: str) -> ErasureSet:
        if len(self.pools) == 1:
            return self.pools[0].set_for(key)
        for p in self.pools:  # an existing object stays in its pool
            try:
                await p.set_for(key).get_object_info(bucket, key)
                return p.set_for(key)
            except errors.S3Error:
                continue
        frees = await asyncio.gather(*[p.free_bytes() for p in self.pools])
        return self.pools[max(range(len(frees)), key=frees.__getitem__)].set_for(key)
