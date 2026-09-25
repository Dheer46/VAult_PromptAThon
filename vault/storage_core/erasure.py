"""Python wrapper around the native erasure coder (diagram box: Erasure Coding)."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

from ..native import Erasure

BLOCK_SIZE = 1 << 20  # 1 MiB

# The native module releases the GIL, so a thread pool gives real parallelism.
_POOL = ThreadPoolExecutor(max_workers=8, thread_name_prefix="erasure")


class ErasureCoder:
    def __init__(self, k: int, m: int, block_size: int = BLOCK_SIZE):
        self.k, self.m, self.n = k, m, k + m
        self.block_size = block_size
        self._e = Erasure(k, m)

    def shard_size(self, block_len: int | None = None) -> int:
        block_len = self.block_size if block_len is None else block_len
        return (block_len + self.k - 1) // self.k

    def shard_file_size(self, total_size: int) -> int:
        """Bytes of shard data one drive stores for an object of total_size."""
        if total_size <= 0:
            return 0
        full, last = divmod(total_size, self.block_size)
        size = full * self.shard_size()
        if last:
            size += self.shard_size(last)
        return size

    def block_lengths(self, total_size: int) -> list[int]:
        full, last = divmod(total_size, self.block_size)
        return [self.block_size] * full + ([last] if last else [])

    def encode_sync(self, block: bytes) -> list[bytes]:
        return self._e.encode_block(block)

    def decode_sync(self, shards: list, block_len: int) -> bytes:
        return self._e.decode_block(shards, block_len)

    def heal_sync(self, shards: list, shard_len: int) -> list[bytes]:
        return self._e.heal_block(shards, shard_len)

    async def encode(self, block: bytes) -> list[bytes]:
        return await asyncio.get_running_loop().run_in_executor(_POOL, self._e.encode_block, block)

    async def decode(self, shards: list, block_len: int) -> bytes:
        return await asyncio.get_running_loop().run_in_executor(
            _POOL, self._e.decode_block, shards, block_len)

    async def heal(self, shards: list, shard_len: int) -> list[bytes]:
        return await asyncio.get_running_loop().run_in_executor(
            _POOL, self._e.heal_block, shards, shard_len)
