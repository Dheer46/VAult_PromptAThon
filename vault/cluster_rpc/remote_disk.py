"""Cluster RPC client: remote drives, remote lockers and peer calls.

One channel per remote node, shared by all its drives. A circuit breaker marks
the node offline after 3 consecutive UNAVAILABLE/timeouts and fails fast for 5 s,
then lets one probe call through. Without it every request would wait for
timeouts on a dead node.
"""
from __future__ import annotations

import json
import time
from typing import AsyncIterator

import grpc

from .. import errors
from ..storage_core.storage_api import StorageAPI
from .auth import make_token
from .proto import pb, rpc
from .server import GRPC_OPTIONS

META_DEADLINE = 10.0
STREAM_DEADLINE = 60.0
BREAKER_FAILS = 3
BREAKER_OPEN_S = 5.0

_ERR = {name: getattr(errors, name) for name in (
    "FileNotFound", "FileVersionNotFound", "VolumeNotFound", "DiskNotFound", "FileCorrupt",
    "VolumeExists", "VolumeNotEmpty", "DiskFull", "UnformattedDisk")}
_ERR["PermissionError"] = PermissionError


class NodeClient:
    def __init__(self, addr: str, self_node: str, secret: str):
        self.addr = addr
        self.self_node = self_node
        self.secret = secret
        self.channel = grpc.aio.insecure_channel(addr, options=GRPC_OPTIONS)
        self.storage = rpc.StorageStub(self.channel)
        self.lock = rpc.LockStub(self.channel)
        self.peer = rpc.PeerStub(self.channel)
        self._fails = 0
        self._open_until = 0.0
        self._token = ("", 0.0)

    @property
    def online(self) -> bool:
        return time.monotonic() >= self._open_until

    def _md(self):
        tok, made = self._token
        if time.time() - made > 300:
            tok = make_token(self.self_node, self.secret)
            self._token = (tok, time.time())
        return (("authorization", f"Bearer {tok}"),)

    def _before(self):
        if time.monotonic() < self._open_until:
            raise errors.DiskNotFound(f"{self.addr} offline (circuit open)")

    def _ok(self):
        self._fails = 0

    def _failed(self):
        self._fails += 1
        if self._fails >= BREAKER_FAILS:
            self._open_until = time.monotonic() + BREAKER_OPEN_S
            self._fails = BREAKER_FAILS - 1  # after the pause, one failed probe re-opens it

    def translate(self, e: grpc.aio.AioRpcError) -> Exception:
        code = e.code()
        if code in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED,
                    grpc.StatusCode.CANCELLED):
            self._failed()
            return errors.DiskNotFound(f"{self.addr}: {code.name}")
        self._ok()
        name, _, msg = (e.details() or "").partition("|")
        cls = _ERR.get(name)
        if cls:
            return cls(msg)
        if code == grpc.StatusCode.UNAUTHENTICATED:
            return errors.DiskNotFound(f"{self.addr}: cluster auth failed")
        return errors.StorageError(f"{self.addr}: {e.details()}")

    async def unary(self, method, request, timeout=META_DEADLINE):
        self._before()
        try:
            resp = await method(request, timeout=timeout, metadata=self._md())
        except grpc.aio.AioRpcError as e:
            raise self.translate(e) from None
        self._ok()
        return resp

    async def close(self):
        await self.channel.close()


class RemoteDisk(StorageAPI):
    is_local = False

    def __init__(self, client: NodeClient, path: str, endpoint: str):
        self.c = client
        self.path = path
        self.endpoint = endpoint
        self.drive_id = ""
        self.faulty = False

    @property
    def online(self) -> bool:
        return self.c.online

    async def disk_info(self) -> dict:
        r = await self.c.unary(self.c.storage.DiskInfo, pb.DiskRef(disk=self.path))
        return {"total": r.total, "free": r.free, "used": r.used, "healing": r.healing,
                "id": r.id or self.drive_id, "formatted": r.formatted, "latency_ms": r.latency_ms,
                "endpoint": self.endpoint, "online": True}

    async def make_vol(self, bucket):
        await self.c.unary(self.c.storage.MakeVol, pb.VolReq(disk=self.path, bucket=bucket))

    async def list_vols(self):
        return list((await self.c.unary(self.c.storage.ListVols, pb.DiskRef(disk=self.path))).names)

    async def stat_vol(self, bucket):
        r = await self.c.unary(self.c.storage.StatVol, pb.VolReq(disk=self.path, bucket=bucket))
        return {"name": r.name, "created": r.created}

    async def delete_vol(self, bucket, force=False):
        await self.c.unary(self.c.storage.DeleteVol, pb.VolReq(disk=self.path, bucket=bucket, force=force))

    async def read_meta(self, bucket, key):
        r = await self.c.unary(self.c.storage.ReadMeta, pb.MetaReq(disk=self.path, bucket=bucket, key=key))
        return r.data

    async def write_meta(self, bucket, key, data):
        await self.c.unary(self.c.storage.WriteMeta,
                           pb.MetaReq(disk=self.path, bucket=bucket, key=key, data=data))

    async def read_all(self, bucket, path):
        r = await self.c.unary(self.c.storage.ReadAll, pb.MetaReq(disk=self.path, bucket=bucket, key=path))
        return r.data

    async def write_all(self, bucket, path, data):
        await self.c.unary(self.c.storage.WriteAll,
                           pb.MetaReq(disk=self.path, bucket=bucket, key=path, data=data))

    async def list_dir(self, bucket, path):
        r = await self.c.unary(self.c.storage.ListDir, pb.MetaReq(disk=self.path, bucket=bucket, key=path))
        return list(r.names)

    async def create_file(self, bucket, path, size, chunks: AsyncIterator[bytes]) -> int:
        self.c._before()

        async def msgs():
            yield pb.FileChunk(disk=self.path, bucket=bucket, path=path, size=size)
            async for ch in chunks:
                yield pb.FileChunk(data=bytes(ch))
        try:
            r = await self.c.storage.CreateFile(msgs(), timeout=None, metadata=self.c._md())
        except grpc.aio.AioRpcError as e:
            raise self.c.translate(e) from None
        self.c._ok()
        return r.value

    async def read_file(self, bucket, path, offset, length, shard_size) -> bytes:
        self.c._before()
        out = bytearray()
        try:
            call = self.c.storage.ReadFile(
                pb.ReadReq(disk=self.path, bucket=bucket, path=path, offset=offset, length=length,
                           shard_size=shard_size), timeout=STREAM_DEADLINE, metadata=self.c._md())
            async for ch in call:
                out += ch.data
        except grpc.aio.AioRpcError as e:
            raise self.c.translate(e) from None
        self.c._ok()
        return bytes(out)

    async def rename_data(self, src_bucket, src_path, meta, dst_bucket, dst_key):
        await self.c.unary(self.c.storage.RenameData, pb.RenameReq(
            disk=self.path, src_bucket=src_bucket, src_path=src_path, meta=meta,
            dst_bucket=dst_bucket, dst_key=dst_key), timeout=STREAM_DEADLINE)

    async def delete(self, bucket, path, recursive=False):
        await self.c.unary(self.c.storage.Delete, pb.DeleteReq(
            disk=self.path, bucket=bucket, path=path, recursive=recursive))

    async def verify_file(self, bucket, path, shard_size, file_size) -> bool:
        r = await self.c.unary(self.c.storage.VerifyFile, pb.VerifyReq(
            disk=self.path, bucket=bucket, path=path, shard_size=shard_size, file_size=file_size),
            timeout=STREAM_DEADLINE * 5)
        return r.ok

    async def walk_dir(self, bucket, prefix=""):
        self.c._before()
        try:
            call = self.c.storage.WalkDir(pb.WalkReq(disk=self.path, bucket=bucket, prefix=prefix),
                                          timeout=STREAM_DEADLINE * 5, metadata=self.c._md())
            async for e in call:
                yield e.key, e.meta
        except grpc.aio.AioRpcError as e:
            raise self.c.translate(e) from None
        self.c._ok()


class RemoteLocker:
    def __init__(self, client: NodeClient):
        self.c = client
        self.name = client.addr

    async def _call(self, method, resource, uid="", owner="", ttl_ms=0, read=False) -> bool:
        r = await self.c.unary(method, pb.LockReq(resource=resource, uid=uid, owner=owner,
                                                  ttl_ms=ttl_ms, read=read), timeout=3.0)
        return r.ok

    async def lock(self, resource, uid, owner, ttl_ms, read):
        return await self._call(self.c.lock.Lock, resource, uid, owner, ttl_ms, read)

    async def unlock(self, resource, uid, owner="", read=False):
        return await self._call(self.c.lock.Unlock, resource, uid, owner, 0, read)

    async def refresh(self, resource, uid, owner, ttl_ms, read=False):
        return await self._call(self.c.lock.Refresh, resource, uid, owner, ttl_ms, read)

    async def force_unlock(self, resource):
        return await self._call(self.c.lock.ForceUnlock, resource)


class PeerClient:
    def __init__(self, client: NodeClient, node: str):
        self.c = client
        self.node = node

    async def notify(self, kind: str, payload: bytes = b"") -> None:
        await self.c.unary(self.c.peer.Notify, pb.PeerMsg(kind=kind, node=self.c.self_node, payload=payload),
                           timeout=5.0)

    async def server_info(self) -> dict:
        r = await self.c.unary(self.c.peer.ServerInfo, pb.Empty(), timeout=5.0)
        return json.loads(r.payload or b"{}")

    async def replication_stats(self) -> dict:
        r = await self.c.unary(self.c.peer.ReplicationStats, pb.Empty(), timeout=5.0)
        return json.loads(r.payload or b"{}")
