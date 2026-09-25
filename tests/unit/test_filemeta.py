"""Phase 3: xl.meta format and the quorum resolver."""
import pytest

from vault import errors
from vault.storage_core.filemeta import (ErasureInfo, FileMeta, FileVersion, ObjectPart,
                                         resolve_filemeta, resolve_version)


def ver(vid="null", t=1, size=10):
    return FileVersion(version_id=vid, mod_time_ns=t, size=size, data_dir=f"dd-{vid}-{t}",
                       erasure=ErasureInfo(k=5, m=3, distribution=list(range(1, 9))),
                       parts=[ObjectPart(1, size, size, f"etag{t}")], meta_user={"etag": f"etag{t}"})


def test_roundtrip_and_corruption():
    fm = FileMeta([ver()])
    raw = fm.marshal()
    assert FileMeta.unmarshal(raw).versions[0].etag == "etag1"
    bad = bytearray(raw)
    bad[-3] ^= 0xFF
    with pytest.raises(errors.FileCorrupt):
        FileMeta.unmarshal(bytes(bad))
    with pytest.raises(errors.FileCorrupt):
        FileMeta.unmarshal(b"XXXX" + raw[4:])


def test_versioning_ops():
    fm = FileMeta()
    assert fm.add_version(ver("null", 1)) == []
    freed = fm.add_version(ver("null", 2))  # unversioned overwrite replaces "null"
    assert freed == ["dd-null-1"] and len(fm.versions) == 1
    fm.add_version(ver("v3", 3))
    assert fm.latest().version_id == "v3"
    dm = fm.add_delete_marker()
    assert fm.latest() is dm and dm.is_delete_marker
    assert fm.delete_version("v3").version_id == "v3"


@pytest.mark.parametrize("stale", [1, 2, 3])
def test_quorum_picks_right_version(stale):
    new = FileMeta([ver("null", 2), ver("old", 1)])
    old = FileMeta([ver("old", 1)])
    metas = [old] * stale + [new] * (8 - stale)
    v, mask = resolve_version(metas, None, read_quorum=5)
    assert v.mod_time_ns == 2
    assert mask == [False] * stale + [True] * (8 - stale)


def test_quorum_not_reached_never_guesses():
    a, b = FileMeta([ver("null", 1)]), FileMeta([ver("null", 2)])
    with pytest.raises(errors.InsufficientReadQuorum):
        resolve_version([a] * 4 + [b] * 4, None, read_quorum=5)
    offline = [errors.DiskNotFound("x")] * 4
    with pytest.raises(errors.InsufficientReadQuorum):
        resolve_version([a] * 4 + offline, None, read_quorum=5)


def test_quorum_not_found():
    missing = [errors.FileNotFound("k")] * 6 + [FileMeta([ver()])] * 2
    v, _ = resolve_version(missing, None, read_quorum=5)
    assert v is None
    fm, _ = resolve_filemeta(missing, 5)
    assert fm is None
