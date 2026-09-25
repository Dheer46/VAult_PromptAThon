"""Single import point for the native core (C++ via pybind11) with a Python fallback."""
from __future__ import annotations

try:  # the compiled extension (ISA-L + BLAKE3), built by scikit-build-core
    import vault_native as _native

    Erasure = _native.Erasure
    hash32 = _native.hash32
    Hasher = _native.Hasher
    NATIVE = True
except ImportError:  # pragma: no cover - exercised on machines without a C++ toolchain
    import blake3 as _blake3

    from .storage_core.rs_py import Erasure  # noqa: F401

    def hash32(data) -> bytes:
        return _blake3.blake3(bytes(data)).digest()

    class Hasher:
        def __init__(self):
            self._h = _blake3.blake3()

        def update(self, data) -> None:
            self._h.update(bytes(data))

        def digest(self) -> bytes:
            return self._h.digest()

        def reset(self) -> None:
            self._h = _blake3.blake3()

    NATIVE = False
