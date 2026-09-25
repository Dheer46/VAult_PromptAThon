"""Phase 5/11/12: one erasure set on 8 local temp drives (EC 5+3) under failures."""
import asyncio
import glob
import os
import shutil

import pytest

from vault import errors
from vault.cluster_rpc.locks import LocalLocker, LockTable, NSLock
from vault.storage_core.disk_store import DiskStore
from vault.storage_core.erasure_set import ErasureSet, PutOpts
from vault.storage_core.filemeta import FileMeta
from vault.storage_core.server_pools import ServerPool, ServerPools
from vault.storage_core.storage_facade import StorageFacade

DEPLOY = "3f1c2b8e-6a1d-4b4e-9d2a-0c9e5f7a1b2c"


class FlakyDisk(DiskStore):
    """Fails create_file after `fail_after` blocks (simulates a drive dying mid-PUT)."""
    fail_after = None

    async def create_file(self, bucket, path, size, chunks):
        if self.fail_after is None:
            return await super().create_file(bucket, path, size, chunks)
        n = 0

        async def limited():
            nonlocal n
            async for c in chunks:
                n += 1
                if n > self.fail_after:
                    raise errors.DiskNotFound("died mid-write")
                yield c
        return await super().create_file(bucket, path, size, limited())


@pytest.fixture
async def env(tmp_path):
    drives = [FlakyDisk(str(tmp_path / f"d{i}"), f"local:d{i}") for i in range(8)]
    ns = NSLock([LocalLocker(LockTable())])
    es = ErasureSet(0, drives, 3, ns)
    facade = StorageFacade(ServerPools([ServerPool(0, [es], DEPLOY)]))
    await facade.make_bucket("b")
    return tmp_path, drives, es, facade


async def gen(data, chunk=65536):
    for i in range(0, len(data), chunk):
        yield data[i:i + chunk]


async def put(es, key, data, **kw):
    return await es.put_object("b", key, gen(data), PutOpts(**kw))


async def get(es, key, offset=0, length=None):
    fv, metas, mask = await es.get_object_info("b", key)
    return b"".join([c async for c in es.read_object("b", key, fv, metas, mask, offset, length)])


SIZES = [0, 1, (1 << 20) - 1, 1 << 20, 10 * (1 << 20) + 7]


@pytest.mark.parametrize("size", SIZES)
async def test_roundtrip_sizes(env, size):
    _, _, es, _ = env
    data = os.urandom(size)
    await put(es, f"k{size}", data)
    assert await get(es, f"k{size}") == data


async def test_range_across_block_boundaries(env):
    _, _, es, _ = env
    data = os.urandom(3 * (1 << 20) + 5)
    await put(es, "r", data)
    for a, n in [((1 << 20) - 3, 10), (5, 2 * (1 << 20)), (len(data) - 1, 1)]:
        assert await get(es, "r", a, n) == data[a:a + n]


async def test_survives_m_lost_drives_but_not_m_plus_1(env):
    tmp, drives, es, _ = env
    data = os.urandom(2 * (1 << 20) + 1)
    await put(es, "k", data)
    for i in range(3):
        shutil.rmtree(tmp / f"d{i}" / "b")
    assert await get(es, "k") == data
    shutil.rmtree(tmp / "d3" / "b")
    with pytest.raises(errors.S3Error) as e:
        await get(es, "k")
    assert e.value.status in (404, 503)


async def test_offline_drives_quorum(env):
    tmp, drives, es, _ = env
    data = os.urandom(500_000)
    await put(es, "k", data)
    saved = list(es.drives)
    es.drives[0] = es.drives[1] = es.drives[2] = None
    assert await get(es, "k") == data
    await put(es, "k2", data)  # write quorum 5 still met
    es.drives[3] = None
    with pytest.raises(errors.S3Error) as e:
        await put(es, "k3", data)
    assert e.value.code == "SlowDown"
    es.drives[:] = saved


async def test_bitrot_is_detected_repaired(env):
    tmp, drives, es, facade = env
    data = os.urandom(2 * (1 << 20))
    await put(es, "rot", data)
    part = sorted(glob.glob(str(tmp / "d*" / "b" / "rot" / "*" / "part.1")))[0]
    with open(part, "r+b") as f:
        f.seek(100)
        b = f.read(1)
        f.seek(100)
        f.write(bytes([b[0] ^ 0xFF]))
    assert await get(es, "rot") == data  # decoded from the others
    assert facade.mrf.qsize() >= 1  # heal queued
    res = await es.heal_object("b", "rot", deep=True)
    assert len(res["healed"]) == 1
    d = next(x for x in drives if x.root in part)
    fv, _, _ = await es.get_object_info("b", "rot")
    from vault.storage_core.erasure import ErasureCoder
    c = ErasureCoder(5, 3)
    assert await d.verify_file("b", f"rot/{fv.data_dir}/part.1", c.shard_size(), c.shard_file_size(len(data)))


async def test_drive_dies_mid_put_then_heals(env):
    tmp, drives, es, facade = env
    drives[2].fail_after = 1
    data = os.urandom(4 * (1 << 20))
    await put(es, "mid", data)  # still succeeds with quorum
    drives[2].fail_after = None
    assert facade.mrf.qsize() >= 1
    metas = await es.read_metas("b", "mid")
    assert sum(isinstance(m, FileMeta) for m in metas) == 7
    await es.heal_object("b", "mid")
    metas = await es.read_metas("b", "mid")
    assert all(isinstance(m, FileMeta) for m in metas)
    es.drives[0] = es.drives[1] = es.drives[3] = None  # healed drive now carries weight
    try:
        assert await get(es, "mid") == data
    finally:
        es.drives[:] = drives


async def test_concurrent_writers_same_key(env):
    _, _, es, _ = env
    payloads = [os.urandom(10_000 + i) for i in range(50)]
    await asyncio.gather(*[put(es, "race", p) for p in payloads])
    final = await get(es, "race")
    assert final in payloads
    await es.heal_object("b", "race")
    metas = await es.read_metas("b", "race")
    assert len({m.signature() for m in metas}) == 1  # all 8 xl.meta agree


async def test_delete_then_stale_drive_healed(env):
    tmp, drives, es, _ = env
    await put(es, "gone", b"x" * 1000)
    saved = es.drives[0]
    es.drives[0] = None  # offline during the delete
    await es.delete_object("b", "gone", None)
    es.drives[0] = saved
    assert isinstance((await es.read_metas("b", "gone"))[0], FileMeta)
    res = await es.heal_object("b", "gone")
    assert res["dangling_removed"]
    assert not any(isinstance(m, FileMeta) for m in await es.read_metas("b", "gone"))


async def test_listing_and_versions(env):
    _, _, es, facade = env
    for k in ["a/1", "a/2", "b/1", "c"]:
        await put(es, k, b"z")
    res = await facade.list_objects("b", delimiter="/")
    assert res.prefixes == ["a/", "b/"] and [o.key for o in res.objects] == ["c"]
    await es.put_object("b", "v", gen(b"1"), PutOpts(version_id="v1"))
    await es.put_object("b", "v", gen(b"2"), PutOpts(version_id="v2"))
    vres = await facade.list_object_versions("b", prefix="v")
    assert [o.version.version_id for o in vres.objects] == ["v2", "v1"]


async def test_crash_between_tmp_and_rename_keeps_old(env, monkeypatch):
    tmp, drives, es, _ = env
    await put(es, "atomic", b"old" * 1000)

    async def boom(*a, **k):
        raise OSError("crash before rename")
    for d in drives:
        monkeypatch.setattr(d, "rename_data", boom)
    with pytest.raises(errors.S3Error):
        await put(es, "atomic", b"new" * 1000)
    monkeypatch.undo()
    assert await get(es, "atomic") == b"old" * 1000


async def test_path_traversal_rejected(tmp_path):
    d = DiskStore(str(tmp_path / "d"))
    with pytest.raises(PermissionError):
        await d.read_all("b", "../../etc/passwd")
