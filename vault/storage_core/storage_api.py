"""The drive interface. Local drives (DiskStore) and remote drives (RemoteDisk,
over Cluster RPC) both implement it, so the Storage Facade doesn't care where a
drive physically is."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import AsyncIterator

SYS_VOL = ".vault.sys"
META_FILE = "xl.meta"
HASH_LEN = 32


class StorageAPI(ABC):
    endpoint: str  # "node2:/data/disk3"
    drive_id: str = ""  # uuid from format.json
    is_local: bool = True

    @abstractmethod
    async def disk_info(self) -> dict: ...

    @abstractmethod
    async def make_vol(self, bucket: str) -> None: ...

    @abstractmethod
    async def list_vols(self) -> list[str]: ...

    @abstractmethod
    async def stat_vol(self, bucket: str) -> dict: ...

    @abstractmethod
    async def delete_vol(self, bucket: str, force: bool = False) -> None: ...

    @abstractmethod
    async def read_meta(self, bucket: str, key: str) -> bytes: ...

    @abstractmethod
    async def write_meta(self, bucket: str, key: str, data: bytes) -> None: ...

    @abstractmethod
    async def read_all(self, bucket: str, path: str) -> bytes: ...

    @abstractmethod
    async def write_all(self, bucket: str, path: str, data: bytes) -> None: ...

    @abstractmethod
    async def create_file(self, bucket: str, path: str, size: int,
                          chunks: AsyncIterator[bytes]) -> int: ...

    @abstractmethod
    async def read_file(self, bucket: str, path: str, offset: int, length: int,
                        shard_size: int) -> bytes: ...

    @abstractmethod
    async def rename_data(self, src_bucket: str, src_path: str, meta: bytes,
                          dst_bucket: str, dst_key: str) -> None: ...

    @abstractmethod
    async def delete(self, bucket: str, path: str, recursive: bool = False) -> None: ...

    @abstractmethod
    async def verify_file(self, bucket: str, path: str, shard_size: int,
                          file_size: int) -> bool: ...

    @abstractmethod
    async def list_dir(self, bucket: str, path: str) -> list[str]: ...

    @abstractmethod
    def walk_dir(self, bucket: str, prefix: str = "") -> AsyncIterator[tuple[str, bytes]]: ...

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.endpoint}>"
