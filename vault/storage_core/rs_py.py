"""Pure-Python (numpy) Reed-Solomon fallback, byte-compatible with the ISA-L build.

Used when the ``vault_native`` extension isn't compiled (e.g. a Windows dev box).
It generates the same Cauchy matrix as ISA-L's ``gf_gen_cauchy1_matrix`` over
GF(2^8) with polynomial 0x11d, so shards written by either implementation are
interchangeable. It is much slower than ISA-L; production images use the native
module.
"""
from __future__ import annotations

import numpy as np

_POLY = 0x11D


def _build_tables():
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= _POLY
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


_EXP, _LOG = _build_tables()


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("gf_inv(0)")
    return _EXP[255 - _LOG[a]]


# MUL[c] is a 256-entry lookup table: MUL[c][x] = c * x in GF(2^8).
_MUL = np.zeros((256, 256), dtype=np.uint8)
for _c in range(256):
    for _x in range(256):
        _MUL[_c, _x] = gf_mul(_c, _x)


def gen_cauchy1_matrix(rows: int, k: int) -> list[list[int]]:
    """Identity on top, Cauchy rows below — identical to ISA-L."""
    mat = [[1 if i == j else 0 for j in range(k)] for i in range(k)]
    for i in range(k, rows):
        mat.append([gf_inv(i ^ j) for j in range(k)])
    return mat


def gf_invert_matrix(mat: list[list[int]]) -> list[list[int]]:
    n = len(mat)
    a = [row[:] for row in mat]
    inv = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    for col in range(n):
        pivot = next((r for r in range(col, n) if a[r][col]), None)
        if pivot is None:
            raise RuntimeError("matrix not invertible")
        a[col], a[pivot] = a[pivot], a[col]
        inv[col], inv[pivot] = inv[pivot], inv[col]
        f = gf_inv(a[col][col])
        a[col] = [gf_mul(f, v) for v in a[col]]
        inv[col] = [gf_mul(f, v) for v in inv[col]]
        for r in range(n):
            if r != col and a[r][col]:
                g = a[r][col]
                a[r] = [x ^ gf_mul(g, y) for x, y in zip(a[r], a[col])]
                inv[r] = [x ^ gf_mul(g, y) for x, y in zip(inv[r], inv[col])]
    return inv


def _mat_apply(coeffs: list[int], src: list[np.ndarray], size: int) -> np.ndarray:
    out = np.zeros(size, dtype=np.uint8)
    for c, s in zip(coeffs, src):
        if c:
            out ^= _MUL[c][s]
    return out


def shard_size_for(block: int, k: int) -> int:
    return (block + k - 1) // k


class Erasure:
    """Same API as ``vault_native.Erasure``."""

    def __init__(self, k: int, m: int):
        if k < 1 or m < 0 or k + m > 255:
            raise ValueError("bad k/m")
        self.k, self.m, self.n = k, m, k + m
        self._matrix = gen_cauchy1_matrix(self.n, k)

    def encode_block(self, data) -> list[bytes]:
        data = bytes(data)
        ss = shard_size_for(len(data), self.k)
        padded = data.ljust(ss * self.k, b"\0")
        arr = np.frombuffer(padded, dtype=np.uint8)
        shards = [arr[i * ss:(i + 1) * ss] for i in range(self.k)]
        out = [s.tobytes() for s in shards]
        for r in range(self.k, self.n):
            out.append(_mat_apply(self._matrix[r], shards, ss).tobytes())
        return out

    def _reconstruct(self, shards: list, ss: int, data_only: bool) -> list[np.ndarray]:
        if len(shards) != self.n:
            raise ValueError("need n shards")
        present = [s is not None for s in shards]
        survivors = [i for i in range(self.n) if present[i]]
        if len(survivors) < self.k:
            raise RuntimeError("not enough shards")
        bufs = [
            np.frombuffer(bytes(s)[:ss].ljust(ss, b"\0"), dtype=np.uint8) if s is not None
            else np.zeros(ss, dtype=np.uint8)
            for s in shards
        ]
        missing = [i for i in range(self.n) if not present[i] and (not data_only or i < self.k)]
        if not missing or ss == 0:
            return bufs
        rows = survivors[: self.k]
        inv = gf_invert_matrix([self._matrix[r] for r in rows])
        src = [bufs[r] for r in rows]
        for i in missing:
            if i < self.k:
                coeffs = inv[i]
            else:
                coeffs = [0] * self.k
                for c in range(self.k):
                    s = 0
                    for j in range(self.k):
                        s ^= gf_mul(self._matrix[i][j], inv[j][c])
                    coeffs[c] = s
            bufs[i] = _mat_apply(coeffs, src, ss)
        return bufs

    def decode_block(self, shards: list, block_len: int) -> bytes:
        ss = shard_size_for(block_len, self.k)
        bufs = self._reconstruct(shards, ss, data_only=True)
        return b"".join(b.tobytes() for b in bufs[: self.k])[:block_len]

    def heal_block(self, shards: list, ss: int) -> list[bytes]:
        return [b.tobytes() for b in self._reconstruct(shards, ss, data_only=False)]
