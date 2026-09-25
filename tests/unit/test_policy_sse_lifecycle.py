"""Policy evaluation, SSE package format, lifecycle rule matching, lock table."""
import os
import time

import pytest

from vault.cluster_rpc.locks import LockTable
from vault.security import policy as pol
from vault.security import sse
from vault.security.lifecycle import LifecycleEngine, parse_lifecycle
from vault.storage_core.filemeta import FileMeta, FileVersion, ObjectPart
from vault.storage_core.metadata_sys import BucketMetadata


def test_policy_allow_deny_wildcards():
    p = {"Statement": [
        {"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::photos/*"},
        {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::photos/secret/*"}]}
    assert pol.is_allowed([p], "s3:GetObject", "arn:aws:s3:::photos/a.jpg", {})
    assert not pol.is_allowed([p], "s3:GetObject", "arn:aws:s3:::photos/secret/x", {})
    assert not pol.is_allowed([p], "s3:PutObject", "arn:aws:s3:::photos/a.jpg", {})


def test_policy_conditions():
    p = {"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::b",
                        "Condition": {"StringLike": {"s3:prefix": "home/alice/*"},
                                      "IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}]}
    ok = {"s3:prefix": "home/alice/docs", "aws:SourceIp": "10.1.2.3"}
    assert pol.is_allowed([p], "s3:ListBucket", "arn:aws:s3:::b", ok)
    assert not pol.is_allowed([p], "s3:ListBucket", "arn:aws:s3:::b", {**ok, "aws:SourceIp": "192.168.0.1"})
    assert not pol.is_allowed([p], "s3:ListBucket", "arn:aws:s3:::b", {**ok, "s3:prefix": "home/bob/"})


def test_bucket_policy_principal():
    bp = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": ["alice"]}, "Action": "s3:GetObject",
                         "Resource": "arn:aws:s3:::b/*"}]}
    assert pol.evaluate([bp], "s3:GetObject", "arn:aws:s3:::b/k", {}, principal="alice") == "allow"
    assert pol.evaluate([bp], "s3:GetObject", "arn:aws:s3:::b/k", {}, principal="*") is None


@pytest.mark.parametrize("size", [0, 1, 65535, 65536, 65537, 300_001])
async def test_sse_roundtrip_and_ranges(size):
    key = os.urandom(32)
    data = os.urandom(size)

    async def src():
        for i in range(0, len(data), 10_000):
            yield data[i:i + 10_000]
    enc = b"".join([c async for c in sse.encrypt_stream(src(), key)])
    assert len(enc) == sse.encrypted_size(size)
    parts = [ObjectPart(1, len(enc), size, "")]

    def read(off, ln):
        async def g():
            yield enc[off:off + ln]
        return g()
    for a, n in [(0, size), (1, size - 2), (65530, 20), (size - 7, 7)]:
        if a < 0 or n <= 0 or a + n > size:
            continue
        out = b"".join([c async for c in sse.decrypt_range(parts, key, a, n, read)])
        assert out == data[a:a + n]


async def test_sse_tamper_detected():
    key = os.urandom(32)

    async def src():
        yield b"x" * 100_000
    enc = bytearray(b"".join([c async for c in sse.encrypt_stream(src(), key)]))
    enc[70_000] ^= 1

    def read(off, ln):
        async def g():
            yield bytes(enc[off:off + ln])
        return g()
    with pytest.raises(Exception):
        _ = [c async for c in sse.decrypt_range([ObjectPart(1, len(enc), 100_000, "")], key, 0, 100_000, read)]


LC = """<LifecycleConfiguration>
 <Rule><ID>exp</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>1</Days></Expiration></Rule>
 <Rule><ID>cold</ID><Status>Enabled</Status><Filter><Prefix>data/</Prefix></Filter>
   <Transition><Days>2</Days><StorageClass>COLD</StorageClass></Transition>
   <NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>
</LifecycleConfiguration>"""


class _S:
    lifecycle_day_seconds = 60


def test_lifecycle_rules():
    rules = parse_lifecycle(LC)
    assert rules[0]["expiration_days"] == 1 and rules[1]["transition_tier"] == "COLD"
    eng = LifecycleEngine(_S(), None, None, None, os.path.join(os.environ.get("TEMP", "/tmp"), "lc-test"))
    bm = BucketMetadata(name="b", lifecycle_xml=LC)
    now = time.time()
    old = FileMeta([FileVersion(mod_time_ns=int((now - 90) * 1e9), size=5, parts=[ObjectPart(1, 5, 5)])])
    assert eng.evaluate(bm, "logs/a", old, now) == [("expire", "null", None)]
    assert eng.evaluate(bm, "data/a", old, now) == []  # 2-"day" transition not yet due
    older = FileMeta([FileVersion(mod_time_ns=int((now - 150) * 1e9), size=5)])
    assert eng.evaluate(bm, "data/a", older, now) == [("transition", "null", "COLD")]
    v = FileMeta([FileVersion("v2", mod_time_ns=int((now - 70) * 1e9)),
                  FileVersion("v1", mod_time_ns=int((now - 200) * 1e9))])
    assert ("expire_version", "v1", None) in eng.evaluate(bm, "data/x", v, now)


def test_lock_table():
    t = LockTable()
    assert t.lock("r", "a", 1000, read=False)
    assert not t.lock("r", "b", 1000, read=False)
    assert not t.lock("r", "c", 1000, read=True)
    assert t.unlock("r", "a")
    assert t.lock("r", "c", 1000, read=True) and t.lock("r", "d", 1000, read=True)
    assert not t.lock("r", "e", 1000, read=False)
    assert t.lock("x", "a", 1, read=False)
    time.sleep(0.01)
    assert t.lock("x", "b", 1000, read=False)  # expired locks don't block forever
