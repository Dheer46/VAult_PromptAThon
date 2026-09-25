"""Cluster RPC server: exposes this node's drives, lock table and peer hooks."""
from __future__ import annotations

import json
from typing import Awaitable, Callable

import grpc

from .. import errors
from ..storage_core.disk_store import DiskStore
from .auth import AuthInterceptor
from .locks import LockTable
from .proto import pb, rpc

GRPC_OPTIONS = [
    ("grpc.max_send_message_length", 16 * 1024 * 1024),
    ("grpc.max_receive_message_length", 16 * 1024 * 1024),
    ("grpc.keepalive_time_ms", 10_000),
    ("grpc.keepalive_timeout_ms", 5_000),
    ("grpc.keepalive_permit_without_calls", 1),
    ("grpc.http2.max_pings_without_data", 0),
]
CHUNK = 1 << 20

# Python exception <-> gRPC status, so the client can rebuild the right type.
_CODES = {
    errors.FileNotFound: grpc.StatusCode.NOT_FOUND,
    errors.FileVersionNotFound: grpc.StatusCode.NOT_FOUND,
    errors.VolumeNotFound: grpc.StatusCode.NOT_FOUND,
    errors.DiskNotFound: grpc.StatusCode.UNAVAILABLE,
    errors.FileCorrupt: grpc.StatusCode.DATA_LOSS,
    errors.VolumeExists: grpc.StatusCode.ALREADY_EXISTS,
    errors.VolumeNotEmpty: grpc.StatusCode.FAILED_PRECONDITION,
    errors.DiskFull: grpc.StatusCode.RESOURCE_EXHAUSTED,
    PermissionError: grpc.StatusCode.PERMISSION_DENIED,
}


async def _abort(context, e: Exception):
    code = next((c for t, c in _CODES.items() if isinstance(e, t)), grpc.StatusCode.INTERNAL)
    await context.abort(code, f"{type(e).__name__}|{e}")


def _guard(fn):
    async def wrapper(self, request, context):
        try:
            return await fn(self, request, context)
        except grpc.aio.AbortError:
            raise
        except Exception as e:
            await _abort(context, e)
    return wrapper


class StorageServicer(rpc.StorageServicer):
    def __init__(self, drives: dict[str, DiskStore]):
        self.drives = drives  # path -> DiskStore

    def _d(self, disk: str) -> DiskStore:
        d = self.drives.get(disk)
        if d is None:
            raise errors.DiskNotFound(disk)
        return d

    @_guard
    async def DiskInfo(self, r, ctx):
        i = await self._d(r.disk).disk_info()
        return pb.DiskInfoResp(total=i["total"], free=i["free"], used=i["used"], healing=i["healing"],
                               id=i["id"], formatted=i["formatted"], latency_ms=i["latency_ms"])

    @_guard
    async def MakeVol(self, r, ctx):
        await self._d(r.disk).make_vol(r.bucket)
        return pb.Empty()

    @_guard
    async def ListVols(self, r, ctx):
        return pb.VolList(names=await self._d(r.disk).list_vols())

    @_guard
    async def StatVol(self, r, ctx):
        i = await self._d(r.disk).stat_vol(r.bucket)
        return pb.VolInfo(name=i["name"], created=i["created"])

    @_guard
    async def DeleteVol(self, r, ctx):
        await self._d(r.disk).delete_vol(r.bucket, r.force)
        return pb.Empty()

    @_guard
    async def ReadMeta(self, r, ctx):
        return pb.MetaResp(data=await self._d(r.disk).read_meta(r.bucket, r.key))

    @_guard
    async def WriteMeta(self, r, ctx):
        await self._d(r.disk).write_meta(r.bucket, r.key, r.data)
        return pb.Empty()

    @_guard
    async def ReadAll(self, r, ctx):
        return pb.MetaResp(data=await self._d(r.disk).read_all(r.bucket, r.key))

    @_guard
    async def WriteAll(self, r, ctx):
        await self._d(r.disk).write_all(r.bucket, r.key, r.data)
        return pb.Empty()

    async def CreateFile(self, request_iterator, ctx):
        try:
            it = request_iterator.__aiter__()
            first = await it.__anext__()
            d = self._d(first.disk)

            async def chunks():
                if first.data:
                    yield first.data
                async for m in it:
                    yield m.data
            n = await d.create_file(first.bucket, first.path, first.size, chunks())
            return pb.IntResp(value=n)
        except grpc.aio.AbortError:
            raise
        except Exception as e:
            await _abort(ctx, e)

    async def ReadFile(self, r, ctx):
        try:
            data = await self._d(r.disk).read_file(r.bucket, r.path, r.offset, r.length, r.shard_size)
        except Exception as e:
            await _abort(ctx, e)
            return
        for i in range(0, max(len(data), 1), CHUNK):
            yield pb.FileChunk(data=data[i:i + CHUNK])

    @_guard
    async def RenameData(self, r, ctx):
        await self._d(r.disk).rename_data(r.src_bucket, r.src_path, r.meta, r.dst_bucket, r.dst_key)
        return pb.Empty()

    @_guard
    async def Delete(self, r, ctx):
        await self._d(r.disk).delete(r.bucket, r.path, r.recursive)
        return pb.Empty()

    @_guard
    async def VerifyFile(self, r, ctx):
        return pb.BoolResp(ok=await self._d(r.disk).verify_file(r.bucket, r.path, r.shard_size, r.file_size))

    async def WalkDir(self, r, ctx):
        try:
            d = self._d(r.disk)
            async for key, meta in d.walk_dir(r.bucket, r.prefix):
                yield pb.WalkEntry(key=key, meta=meta)
        except Exception as e:
            await _abort(ctx, e)

    @_guard
    async def ListDir(self, r, ctx):
        return pb.ListDirResp(names=await self._d(r.disk).list_dir(r.bucket, r.key))


class LockServicer(rpc.LockServicer):
    def __init__(self, table: LockTable):
        self.t = table

    async def Lock(self, r, ctx):
        return pb.BoolResp(ok=self.t.lock(r.resource, r.uid, r.ttl_ms, r.read))

    async def Unlock(self, r, ctx):
        return pb.BoolResp(ok=self.t.unlock(r.resource, r.uid))

    async def Refresh(self, r, ctx):
        return pb.BoolResp(ok=self.t.refresh(r.resource, r.uid, r.ttl_ms))

    async def ForceUnlock(self, r, ctx):
        return pb.BoolResp(ok=self.t.force_unlock(r.resource))


class PeerServicer(rpc.PeerServicer):
    """Notify handlers are registered by services: kind -> async fn(payload: bytes)."""

    def __init__(self, node: str):
        self.node = node
        self.handlers: dict[str, Callable[[bytes], Awaitable[None]]] = {}
        self.server_info: Callable[[], Awaitable[dict]] | None = None
        self.replication_stats: Callable[[], Awaitable[dict]] | None = None

    @_guard
    async def Notify(self, r, ctx):
        h = self.handlers.get(r.kind)
        if h:
            await h(r.payload)
        return pb.Empty()

    @_guard
    async def ServerInfo(self, r, ctx):
        info = await self.server_info() if self.server_info else {}
        return pb.PeerMsg(kind="server-info", node=self.node, payload=json.dumps(info).encode())

    @_guard
    async def ReplicationStats(self, r, ctx):
        info = await self.replication_stats() if self.replication_stats else {}
        return pb.PeerMsg(kind="replication-stats", node=self.node, payload=json.dumps(info).encode())


async def start_server(port: int, drives: dict[str, DiskStore], table: LockTable,
                       peer: PeerServicer, secret: str) -> grpc.aio.Server:
    server = grpc.aio.server(options=GRPC_OPTIONS, interceptors=[AuthInterceptor(secret)])
    rpc.add_StorageServicer_to_server(StorageServicer(drives), server)
    rpc.add_LockServicer_to_server(LockServicer(table), server)
    rpc.add_PeerServicer_to_server(peer, server)
    server.add_insecure_port(f"[::]:{port}")
    await server.start()
    return server
