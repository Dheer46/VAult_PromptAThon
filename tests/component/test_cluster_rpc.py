"""Phase 4: 4 "nodes" in one process on different ports, talking gRPC:
remote drives, distributed locks, partitions and the circuit breaker."""
import asyncio
import os
import time

import pytest

from vault import errors
from vault.cluster_rpc.locks import DistributedLock, LockTable
from vault.cluster_rpc.remote_disk import NodeClient, RemoteDisk, RemoteLocker
from vault.cluster_rpc.server import PeerServicer, start_server
from vault.storage_core.disk_store import DiskStore
from vault.storage_core.erasure_set import ErasureSet, PutOpts
from tests.conftest import free_port

SECRET = "test-cluster-secret"


@pytest.fixture
async def cluster(tmp_path):
    nodes = []
    for n in range(4):
        port = free_port()
        drives = {f"/d{i}": DiskStore(str(tmp_path / f"n{n}" / f"d{i}"), f"n{n}:/d{i}") for i in range(2)}
        table = LockTable()
        srv = await start_server(port, drives, table, PeerServicer(f"n{n}"), SECRET)
        nodes.append({"port": port, "srv": srv, "drives": drives, "table": table})
    clients = [NodeClient(f"127.0.0.1:{n['port']}", "tester", SECRET) for n in nodes]
    yield nodes, clients
    for c in clients:
        await c.close()
    for n in nodes:
        await n["srv"].stop(0)


async def gen(data):
    for i in range(0, len(data), 65536):
        yield data[i:i + 65536]


async def test_remote_erasure_set_roundtrip(cluster):
    nodes, clients = cluster
    # 8 drives, round-robin across the 4 nodes (2 per node)
    remote = [RemoteDisk(clients[i % 4], f"/d{i // 4}", f"n{i % 4}:/d{i // 4}") for i in range(8)]
    lockers = [RemoteLocker(c) for c in clients]
    from vault.cluster_rpc.locks import NSLock
    es = ErasureSet(0, remote, 3, NSLock(lockers))
    await es._each(lambda d: d.make_vol("b"))
    data = os.urandom(3 * (1 << 20) + 17)
    await es.put_object("b", "obj", gen(data), PutOpts())
    fv, metas, mask = await es.get_object_info("b", "obj")
    out = b"".join([c async for c in es.read_object("b", "obj", fv, metas, mask)])
    assert out == data
    entries = await es.list_entries("b")
    assert [k for k, _ in entries] == ["obj"]
    # lose one whole node (2 drives of this set): still readable
    await nodes[1]["srv"].stop(0)
    fv, metas, mask = await es.get_object_info("b", "obj")
    out = b"".join([c async for c in es.read_object("b", "obj", fv, metas, mask)])
    assert out == data


async def test_distributed_lock_exclusive(cluster):
    _, clients = cluster
    lockers = [RemoteLocker(c) for c in clients]
    holders = []
    active = 0

    async def worker(i):
        nonlocal active
        lk = await DistributedLock(lockers, "b/key").acquire(timeout=20)
        active += 1
        assert active == 1  # exactly one holder at a time
        holders.append(i)
        await asyncio.sleep(0.01)
        active -= 1
        await lk.release()
    await asyncio.gather(*[worker(i) for i in range(10)])
    assert sorted(holders) == list(range(10))


async def test_lock_quorum_with_dead_nodes(cluster):
    nodes, clients = cluster
    lockers = [RemoteLocker(c) for c in clients]
    await nodes[3]["srv"].stop(0)
    lk = await DistributedLock(lockers, "r1").acquire(timeout=5)  # 3 of 4 = quorum
    await lk.release()
    await nodes[2]["srv"].stop(0)
    with pytest.raises(errors.S3Error) as e:  # 2 of 4 < quorum -> writes rejected
        await DistributedLock(lockers, "r2").acquire(timeout=1)
    assert e.value.code == "SlowDown"


async def test_circuit_breaker_fails_fast(cluster):
    nodes, clients = cluster
    await nodes[0]["srv"].stop(0)
    d = RemoteDisk(clients[0], "/d0", "n0:/d0")
    for _ in range(3):
        with pytest.raises(errors.DiskNotFound):
            await d.disk_info()
    t = time.perf_counter()
    with pytest.raises(errors.DiskNotFound):
        await d.disk_info()
    assert time.perf_counter() - t < 0.05


async def test_bad_cluster_secret_rejected(cluster):
    nodes, _ = cluster
    c = NodeClient(f"127.0.0.1:{nodes[0]['port']}", "evil", "wrong-secret")
    with pytest.raises(errors.DiskNotFound):
        await RemoteDisk(c, "/d0", "x").disk_info()
    await c.close()
