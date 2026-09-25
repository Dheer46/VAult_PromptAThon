"""Streaming encryption format (SSE).

Plaintext is encrypted in 64 KiB packages with AES-256-GCM:
    package = nonce(12) || ciphertext || tag(16)      -> 28 bytes overhead each
    AAD     = part number (4) || package sequence (8) || final flag (1)
Encrypted size = plain + ceil(plain / 65536) * 28. A plaintext range [a, b] maps
to packages a // 65536 .. b // 65536, so range GETs fetch and decrypt only those.
Multipart objects encrypt each part independently (sequence restarts per part).
"""
from __future__ import annotations

import base64
import hashlib
import os
import struct
from dataclasses import dataclass
from typing import AsyncIterator, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .. import errors

PKG = 64 * 1024
OVERHEAD = 28
ENC_PKG = PKG + OVERHEAD


def encrypted_size(plain: int) -> int:
    return plain + -(-plain // PKG) * OVERHEAD


def _aad(part: int, seq: int, final: bool) -> bytes:
    return struct.pack(">IQ?", part, seq, final)


async def encrypt_stream(reader: AsyncIterator[bytes], key: bytes, part: int = 1
                         ) -> AsyncIterator[bytes]:
    aead = AESGCM(key)
    buf = bytearray()
    seq = 0
    pending: bytes | None = None  # hold one package back to know which one is final

    def seal(chunk: bytes, final: bool) -> bytes:
        nonce = os.urandom(12)
        return nonce + aead.encrypt(nonce, chunk, _aad(part, seq, final))

    async for chunk in reader:
        buf += chunk
        while len(buf) >= PKG:
            if pending is not None:
                yield seal(pending, False)
                seq += 1
            pending = bytes(buf[:PKG])
            del buf[:PKG]
    if buf:
        if pending is not None:
            yield seal(pending, False)
            seq += 1
        yield seal(bytes(buf), True)
    elif pending is not None:
        yield seal(pending, True)


def decrypt_package(aead: AESGCM, enc: bytes, part: int, seq: int, final: bool) -> bytes:
    try:
        return aead.decrypt(enc[:12], enc[12:], _aad(part, seq, final))
    except Exception:
        raise errors.S3Error("InternalError", "encrypted package failed authentication", 500)


@dataclass
class PartLayout:
    number: int
    plain: int  # plaintext size
    stored: int  # encrypted size
    stored_offset: int  # where this part starts in the stored object


def layout(parts: list) -> list[PartLayout]:
    out, off = [], 0
    for p in parts:
        out.append(PartLayout(p.number, p.actual_size, p.size, off))
        off += p.size
    return out


async def decrypt_range(parts: list, key: bytes, offset: int, length: int,
                        read: Callable[[int, int], AsyncIterator[bytes]]) -> AsyncIterator[bytes]:
    """Yield plaintext [offset, offset+length). `read(stored_off, stored_len)` streams
    stored (encrypted) bytes."""
    aead = AESGCM(key)
    end = offset + length
    pos = 0
    for pl in layout(parts):
        p0, p1 = pos, pos + pl.plain
        pos = p1
        if p1 <= offset or p0 >= end or pl.plain == 0:
            continue
        lo, hi = max(offset, p0) - p0, min(end, p1) - p0  # range inside this part
        first, last = lo // PKG, (hi - 1) // PKG
        npk = -(-pl.plain // PKG)
        s_off = pl.stored_offset + first * ENC_PKG
        s_len = min(pl.stored_offset + pl.stored, pl.stored_offset + (last + 1) * ENC_PKG) - s_off
        buf = bytearray()
        seq = first
        async for chunk in read(s_off, s_len):
            buf += chunk
            while seq <= last:
                size = ENC_PKG if seq < npk - 1 else (pl.plain - (npk - 1) * PKG) + OVERHEAD
                if len(buf) < size:
                    break
                plain = decrypt_package(aead, bytes(buf[:size]), pl.number, seq, seq == npk - 1)
                del buf[:size]
                a = lo - seq * PKG if seq == first else 0
                b = hi - seq * PKG if seq == last else len(plain)
                yield plain[a:b]
                seq += 1
        if seq <= last:
            raise errors.S3Error("InternalError", "truncated encrypted object", 500)


# ------------------------------------------------------------------ SSE-C
def parse_ssec(headers, prefix: str = "x-amz-server-side-encryption-customer-") -> tuple[bytes, str] | None:
    algo = headers.get(prefix + "algorithm")
    if not algo:
        return None
    if algo != "AES256":
        raise errors.S3Error("InvalidEncryptionAlgorithmError", "SSE-C algorithm must be AES256")
    try:
        key = base64.b64decode(headers.get(prefix + "key", ""))
    except Exception:
        raise errors.S3Error("InvalidArgument", "bad SSE-C key")
    md5 = headers.get(prefix + "key-md5", "")
    if len(key) != 32 or base64.b64encode(hashlib.md5(key).digest()).decode() != md5:
        raise errors.S3Error("InvalidArgument", "SSE-C key or MD5 invalid")
    return key, md5
