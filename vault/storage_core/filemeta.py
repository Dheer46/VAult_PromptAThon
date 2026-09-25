"""xl.meta: every version of an object, stored next to the shards on each drive
(diagram box: Object Metadata).

Binary format: b"VLT1" + first 8 bytes of BLAKE3(payload) + msgpack(payload).
The checksum means a corrupted xl.meta is detected just like a corrupted shard.
"""
from __future__ import annotations

import json
import time
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Sequence

import msgpack

from .. import errors
from ..native import hash32

MAGIC = b"VLT1"
NULL_VERSION = "null"
INLINE_THRESHOLD = 128 * 1024

# Well-known internal keys in FileVersion.meta_sys
SSE_KEY = "x-vault-internal-sse"
REPL_STATUS = "x-vault-replication-status"
TRANSITION_STATUS = "x-vault-transition-status"
TRANSITIONED_OBJECT = "x-vault-transitioned-object"
HEALED_AT = "x-vault-healed"


@dataclass
class ErasureInfo:
    algo: str = "rs-cauchy-isal"
    k: int = 0
    m: int = 0
    block_size: int = 1 << 20
    index: int = 0  # this drive's shard index (1..n)
    distribution: list[int] = field(default_factory=list)  # shard index per drive position
    checksums: list[dict] = field(default_factory=list)  # per part: {"part": 1, "algo": ...}


@dataclass
class ObjectPart:
    number: int
    size: int  # stored (possibly encrypted) size of the part
    actual_size: int  # size before compression/encryption
    etag: str = ""


@dataclass
class FileVersion:
    version_id: str = NULL_VERSION
    type: str = "object"  # "object" | "delete_marker"
    mod_time_ns: int = 0
    size: int = 0
    data_dir: str = ""  # uuid of the directory holding part files
    erasure: ErasureInfo | None = None
    parts: list[ObjectPart] = field(default_factory=list)
    meta_sys: dict = field(default_factory=dict)  # internal: encryption, replication, tier info
    meta_user: dict = field(default_factory=dict)  # x-amz-meta-*, content-type, etag
    inline_data: bytes | None = None  # small objects stored inside xl.meta

    @property
    def is_delete_marker(self) -> bool:
        return self.type == "delete_marker"

    @property
    def etag(self) -> str:
        return self.meta_user.get("etag", "")

    @property
    def is_inline(self) -> bool:
        return self.inline_data is not None

    def signature(self) -> tuple:
        return (self.version_id, self.mod_time_ns, self.data_dir, self.size, self.type,
                tuple(p.etag for p in self.parts),
                json.dumps(self.meta_sys, sort_keys=True, default=str),
                json.dumps(self.meta_user, sort_keys=True, default=str))

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @staticmethod
    def from_dict(d: dict) -> "FileVersion":
        d = dict(d)
        er = d.get("erasure")
        d["erasure"] = ErasureInfo(**er) if er else None
        d["parts"] = [ObjectPart(**p) for p in d.get("parts") or []]
        return FileVersion(**d)

    def copy_for_drive(self, index: int, inline: bytes | None) -> "FileVersion":
        v = FileVersion.from_dict(self.to_dict())
        if v.erasure:
            v.erasure.index = index
        v.inline_data = inline
        return v


def new_version_id() -> str:
    return str(uuid.uuid4())


def now_ns() -> int:
    return time.time_ns()


@dataclass
class FileMeta:
    versions: list[FileVersion] = field(default_factory=list)  # newest first

    def marshal(self) -> bytes:
        payload = msgpack.packb({"v": 1, "versions": [v.to_dict() for v in self.versions]},
                                use_bin_type=True)
        return MAGIC + hash32(payload)[:8] + payload

    @staticmethod
    def unmarshal(raw: bytes) -> "FileMeta":
        if len(raw) < 12 or raw[:4] != MAGIC:
            raise errors.FileCorrupt("xl.meta: bad magic")
        payload = raw[12:]
        if hash32(payload)[:8] != raw[4:12]:
            raise errors.FileCorrupt("xl.meta: checksum mismatch")
        d = msgpack.unpackb(payload, raw=False)
        return FileMeta([FileVersion.from_dict(v) for v in d["versions"]])

    # ----------------------------------------------------------- versioning
    def _sort(self) -> None:
        self.versions.sort(key=lambda v: (v.mod_time_ns, v.version_id), reverse=True)

    def add_version(self, v: FileVersion) -> list[str]:
        """Insert v; a version with the same id (e.g. "null") is replaced.
        Returns data dirs that are no longer referenced."""
        freed = []
        for old in [x for x in self.versions if x.version_id == v.version_id]:
            self.versions.remove(old)
            if old.data_dir and old.data_dir != v.data_dir:
                freed.append(old.data_dir)
        self.versions.append(v)
        self._sort()
        return freed

    def find(self, version_id: str | None) -> FileVersion | None:
        if not version_id:
            return self.versions[0] if self.versions else None
        for v in self.versions:
            if v.version_id == version_id:
                return v
        return None

    def delete_version(self, version_id: str) -> FileVersion | None:
        v = self.find(version_id)
        if v is not None:
            self.versions.remove(v)
        return v

    def add_delete_marker(self, version_id: str | None = None) -> FileVersion:
        dm = FileVersion(version_id=version_id or new_version_id(), type="delete_marker",
                         mod_time_ns=now_ns())
        self.add_version(dm)
        return dm

    def latest(self) -> FileVersion | None:
        """Newest version; None if there are none. Callers check is_delete_marker."""
        return self.versions[0] if self.versions else None

    def signature(self) -> tuple:
        return tuple(v.signature() for v in self.versions)

    def data_dirs(self) -> set[str]:
        return {v.data_dir for v in self.versions if v.data_dir}


# ------------------------------------------------------------------ quorum
_MISSING = ("__missing__",)


def load_metas(results: Sequence[Any]) -> list[FileMeta | Exception]:
    """Turn raw read_meta results (bytes or exceptions) into FileMeta or exceptions."""
    out: list[FileMeta | Exception] = []
    for r in results:
        if isinstance(r, BaseException):
            out.append(r if isinstance(r, Exception) else Exception(str(r)))
            continue
        try:
            out.append(FileMeta.unmarshal(r))
        except errors.FileCorrupt as e:
            out.append(e)
    return out


def resolve_version(metas: list[FileMeta | Exception], version_id: str | None,
                    read_quorum: int) -> tuple[FileVersion | None, list[bool]]:
    """Quorum FileInfo: pick the version that >= read_quorum drives agree on.

    Returns (version, agree_mask). version is None when a quorum of drives says the
    object/version doesn't exist. Raises InsufficientReadQuorum when no answer
    reaches quorum (never guess)."""
    sigs: list[tuple | None] = []
    for fm in metas:
        if isinstance(fm, FileMeta):
            v = fm.find(version_id)
            sigs.append(v.signature() if v else _MISSING)
        elif isinstance(fm, (errors.FileNotFound, errors.VolumeNotFound)):
            sigs.append(_MISSING)
        else:
            sigs.append(None)  # drive error: doesn't vote
    counts = Counter(s for s in sigs if s is not None)
    if not counts:
        raise errors.InsufficientReadQuorum("no drives answered")
    best, n = counts.most_common(1)[0]
    if n < read_quorum:
        raise errors.InsufficientReadQuorum(f"best answer has {n}/{read_quorum} drives")
    mask = [s == best for s in sigs]
    if best == _MISSING:
        return None, mask
    for fm, ok in zip(metas, mask):
        if ok:
            return fm.find(version_id), mask
    raise AssertionError("unreachable")


def resolve_filemeta(metas: list[FileMeta | Exception],
                     read_quorum: int) -> tuple[FileMeta | None, list[bool]]:
    """Whole-object agreement (used by healing): all versions must match."""
    sigs: list[tuple | None] = []
    for fm in metas:
        if isinstance(fm, FileMeta):
            sigs.append(fm.signature() if fm.versions else _MISSING)
        elif isinstance(fm, (errors.FileNotFound, errors.VolumeNotFound)):
            sigs.append(_MISSING)
        else:
            sigs.append(None)
    counts = Counter(s for s in sigs if s is not None)
    if not counts:
        raise errors.InsufficientReadQuorum("no drives answered")
    best, n = counts.most_common(1)[0]
    if n < read_quorum:
        raise errors.InsufficientReadQuorum(f"best answer has {n}/{read_quorum} drives")
    mask = [s == best for s in sigs]
    if best == _MISSING:
        return None, mask
    return next(fm for fm, ok in zip(metas, mask) if ok), mask
