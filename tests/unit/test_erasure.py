"""Phase 1: erasure coding math (native module when built, else the numpy fallback)."""
import os
import random
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vault.native import NATIVE, Erasure, hash32
from vault.storage_core import rs_py


@settings(max_examples=40, deadline=None)
@given(data=st.binary(min_size=0, max_size=300_000), k=st.integers(2, 12), m=st.integers(1, 4),
       seed=st.integers(0, 2 ** 32))
def test_encode_drop_decode(data, k, m, seed):
    e = Erasure(k, m)
    shards = e.encode_block(data)
    assert len(shards) == k + m
    rnd = random.Random(seed)
    lost = rnd.sample(range(k + m), rnd.randint(0, m))
    damaged = [None if i in lost else s for i, s in enumerate(shards)]
    assert e.decode_block(damaged, len(data)) == data
    healed = e.heal_block(damaged, len(shards[0]))
    assert healed == shards  # exact bytes of dropped data AND parity shards


def test_too_many_lost():
    e = Erasure(5, 3)
    shards = e.encode_block(os.urandom(10_000))
    damaged = [None] * 4 + shards[4:]
    with pytest.raises(Exception):
        e.decode_block(damaged, 10_000)


def test_matches_isal_matrix():
    """The fallback must produce ISA-L-identical parity (Cauchy1 over GF(2^8), poly 0x11d)."""
    m = rs_py.gen_cauchy1_matrix(8, 5)
    assert m[5] == [rs_py.gf_inv(5 ^ j) for j in range(5)]
    assert rs_py.gf_mul(0x57, 0x83) == 0x31  # a known GF(2^8)/0x11d product
    if NATIVE:
        data = os.urandom(1 << 20)
        assert rs_py.Erasure(5, 3).encode_block(data) == Erasure(5, 3).encode_block(data)


def test_hash32_is_blake3():
    import blake3
    d = os.urandom(5000)
    assert hash32(d) == blake3.blake3(d).digest()


def test_benchmark_prints_throughput(capsys):
    e = Erasure(5, 3)
    block = os.urandom(1 << 20)
    n = 50 if NATIVE else 5
    t = time.perf_counter()
    for _ in range(n):
        e.encode_block(block)
    mbps = n / (time.perf_counter() - t)
    print(f"EC 5+3 encode: {mbps:.0f} MiB/s (native={NATIVE})")
    assert mbps > 0
