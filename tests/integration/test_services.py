"""Background services end to end, with a second Vault node standing in for Remote S3:
replication (#8, #11, #12), lifecycle tiering (#15), drive heal (#9, #10), deep scan."""
import asyncio
import glob
import os
import shutil
import time
import uuid

import pytest

from tests.conftest import ROOT_PASS, ROOT_USER, ServerThread, make_s3
from vault.admin.vaultctl import Client


@pytest.fixture(scope="module")
def remote(tmp_path_factory):
    """Remote S3 (in production: a real AWS S3 bucket in another region, or MinIO)."""
    srv = ServerThread(str(tmp_path_factory.mktemp("remote"))).start()
    yield srv
    srv.stop()


@pytest.fixture(scope="module")
def local(tmp_path_factory):
    srv = ServerThread(str(tmp_path_factory.mktemp("local")), scanner_deep_every=1,
                       scanner_heal_every=1, scanner_speed=1.0).start()
    yield srv
    srv.stop()


def wait_for(fn, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def test_bucket_replication_to_remote_s3(local, remote):
    s3, rs3 = make_s3(local.endpoint), make_s3(remote.endpoint)
    src, dst = f"src-{uuid.uuid4().hex[:6]}", f"replica-{uuid.uuid4().hex[:6]}"
    rs3.create_bucket(Bucket=dst)
    s3.create_bucket(Bucket=src)
    s3.put_bucket_versioning(Bucket=src, VersioningConfiguration={"Status": "Enabled"})
    admin = Client(local.endpoint, ROOT_USER, ROOT_PASS)
    arn = admin.call("PUT", f"replication/targets/{src}", {
        "endpoint": remote.endpoint, "bucket": dst, "access_key": ROOT_USER, "secret_key": ROOT_PASS})["arn"]
    s3.put_bucket_replication(Bucket=src, ReplicationConfiguration={"Role": "", "Rules": [{
        "ID": "all", "Status": "Enabled", "Priority": 1, "Filter": {"Prefix": ""},
        "DeleteMarkerReplication": {"Status": "Enabled"},
        "Destination": {"Bucket": arn}}]})
    data = os.urandom(300_000)
    s3.put_object(Bucket=src, Key="photos/cat.jpg", Body=data, Metadata={"who": "cat"})
    assert wait_for(lambda: rs3.get_object(Bucket=dst, Key="photos/cat.jpg")["Body"].read() == data)
    remote_obj = rs3.head_object(Bucket=dst, Key="photos/cat.jpg")
    assert remote_obj["Metadata"]["who"] == "cat"
    assert remote_obj["ReplicationStatus"] == "REPLICA"  # never re-replicated
    assert wait_for(lambda: s3.head_object(Bucket=src, Key="photos/cat.jpg")["ReplicationStatus"] == "COMPLETED")
    m = admin.call("GET", "replication/metrics")
    assert m["total"]["completed"] >= 1
    # delete marker replication
    s3.delete_object(Bucket=src, Key="photos/cat.jpg")
    assert wait_for(lambda: "Contents" not in rs3.list_objects_v2(Bucket=dst))


def test_replication_backlog_grows_and_drains(local, remote):
    s3, rs3 = make_s3(local.endpoint), make_s3(remote.endpoint)
    src, dst = f"src-{uuid.uuid4().hex[:6]}", f"replica-{uuid.uuid4().hex[:6]}"
    s3.create_bucket(Bucket=src)
    s3.put_bucket_versioning(Bucket=src, VersioningConfiguration={"Status": "Enabled"})
    admin = Client(local.endpoint, ROOT_USER, ROOT_PASS)
    arn = admin.call("PUT", f"replication/targets/{src}", {   # target bucket doesn't exist yet
        "endpoint": remote.endpoint, "bucket": dst, "access_key": ROOT_USER, "secret_key": ROOT_PASS})["arn"]
    s3.put_bucket_replication(Bucket=src, ReplicationConfiguration={"Role": "", "Rules": [{
        "ID": "r", "Status": "Enabled", "Priority": 1, "Filter": {"Prefix": ""},
        "DeleteMarkerReplication": {"Status": "Disabled"}, "Destination": {"Bucket": arn}}]})
    for i in range(5):
        s3.put_object(Bucket=src, Key=f"k{i}", Body=b"x" * 100)
    assert wait_for(lambda: admin.call("GET", "replication/metrics")["total"]["queued_count"] >= 5, 5)
    rs3.create_bucket(Bucket=dst)  # "restore network access"
    assert wait_for(lambda: len(rs3.list_objects_v2(Bucket=dst).get("Contents", [])) == 5, 40)
    assert wait_for(lambda: admin.call("GET", "replication/metrics")["total"]["queued_count"] == 0, 10)


def test_lifecycle_transition_to_remote_tier(local, remote):
    s3, rs3 = make_s3(local.endpoint), make_s3(remote.endpoint)
    tier_bucket = f"cold-{uuid.uuid4().hex[:6]}"
    rs3.create_bucket(Bucket=tier_bucket)
    admin = Client(local.endpoint, ROOT_USER, ROOT_PASS)
    admin.call("PUT", "tiers/COLD", {"type": "s3", "endpoint": remote.endpoint, "bucket": tier_bucket,
                                     "prefix": "cluster1/", "access_key": ROOT_USER, "secret_key": ROOT_PASS})
    b = f"lc-{uuid.uuid4().hex[:6]}"
    s3.create_bucket(Bucket=b)
    data = os.urandom(2 * (1 << 20) + 3)
    s3.put_object(Bucket=b, Key="data/big.bin", Body=data, ServerSideEncryption="AES256")
    s3.put_object(Bucket=b, Key="logs/old.log", Body=b"old log")
    s3.put_bucket_lifecycle_configuration(Bucket=b, LifecycleConfiguration={"Rules": [
        {"ID": "tier", "Status": "Enabled", "Filter": {"Prefix": "data/"},
         "Transitions": [{"Days": 1, "StorageClass": "COLD"}]},
        {"ID": "expire", "Status": "Enabled", "Filter": {"Prefix": "logs/"}, "Expiration": {"Days": 1}}]})
    local.node.settings.lifecycle_day_seconds = 0  # make "1 day" pass immediately
    try:
        local.run(local.node.scanner.scan_cycle(), timeout=120)
    finally:
        local.node.settings.lifecycle_day_seconds = 86400
    remote_objs = rs3.list_objects_v2(Bucket=tier_bucket).get("Contents", [])
    assert len(remote_objs) == 1 and remote_objs[0]["Key"].startswith("cluster1/")
    h = s3.head_object(Bucket=b, Key="data/big.bin")
    assert h["StorageClass"] == "COLD"
    assert s3.get_object(Bucket=b, Key="data/big.bin")["Body"].read() == data  # proxied from the tier
    assert s3.get_object(Bucket=b, Key="data/big.bin", Range="bytes=100-200")["Body"].read() == data[100:201]
    local_parts = glob.glob(os.path.join(local.tmp, "disk*", b, "data", "big.bin", "*", "part.*"))
    assert local_parts == []  # local disk usage dropped
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=b).get("Contents", [])]
    assert "logs/old.log" not in keys  # expired


def test_wiped_drive_is_detected_and_healed(local):
    s3 = make_s3(local.endpoint)
    b = f"heal-{uuid.uuid4().hex[:6]}"
    s3.create_bucket(Bucket=b)
    objs = {f"o{i}": os.urandom(50_000 + i * 70_000) for i in range(12)}
    for k, v in objs.items():
        s3.put_object(Bucket=b, Key=k, Body=v)
    drive = os.path.join(local.tmp, "disk3")
    for name in os.listdir(drive):  # docker exec node2 rm -rf /data/disk3/*
        shutil.rmtree(os.path.join(drive, name), ignore_errors=True)

    async def heal():
        tasks = await local.node.healing.check_drives_once()
        await asyncio.gather(*tasks)
    local.run(heal(), timeout=120)
    assert os.path.exists(os.path.join(drive, ".vault.sys", "format.json"))
    st = local.node.healing.status
    assert any(v.get("progress") == 1.0 for v in st.values())
    for k in objs:
        assert glob.glob(os.path.join(drive, b, k, "xl.meta")), k
    # now lose 3 *other* drives' copies: the healed drive must carry its weight
    for i in (1, 2, 4):
        shutil.rmtree(os.path.join(local.tmp, f"disk{i}", b), ignore_errors=True)
    for k, v in objs.items():
        assert s3.get_object(Bucket=b, Key=k)["Body"].read() == v
    local.run(local.node.storage.heal_bucket(b))
    for k in objs:
        local.run(local.node.storage.heal_object(b, k))


def test_deep_scan_repairs_bitrot(local):
    s3 = make_s3(local.endpoint)
    b = f"rot-{uuid.uuid4().hex[:6]}"
    s3.create_bucket(Bucket=b)
    data = os.urandom(3 * (1 << 20))
    s3.put_object(Bucket=b, Key="k", Body=data)
    part = sorted(glob.glob(os.path.join(local.tmp, "disk*", b, "k", "*", "part.1")))[2]
    with open(part, "r+b") as f:
        f.seek(5000)
        f.write(b"\x00\xff\x00\xff")
    local.run(local.node.scanner.scan_cycle(), timeout=120)

    async def drain():
        for _ in range(100):
            if local.node.healing.queue.empty():
                await asyncio.sleep(0.5)
                return
            await asyncio.sleep(0.1)
    local.run(drain())
    d = next(x for x in local.node.local_drives.values() if part.startswith(x.root))
    from vault.storage_core.erasure import ErasureCoder
    c = ErasureCoder(5, 3)
    rel = os.path.relpath(part, os.path.join(d.root, b)).replace(os.sep, "/")
    ok = local.run(d.verify_file(b, rel, c.shard_size(), c.shard_file_size(len(data))))
    assert ok
    assert s3.get_object(Bucket=b, Key="k")["Body"].read() == data
