"""Loads the generated gRPC modules, generating them from vault.proto on first use.

Equivalent to:
  python -m grpc_tools.protoc -I vault/cluster_rpc --python_out=vault/cluster_rpc/generated \
      --grpc_python_out=vault/cluster_rpc/generated vault/cluster_rpc/vault.proto
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_GEN = os.path.join(_HERE, "generated")
_PROTO = os.path.join(_HERE, "vault.proto")


def _generate() -> None:
    from grpc_tools import protoc
    import grpc_tools
    include = os.path.join(os.path.dirname(grpc_tools.__file__), "_proto")
    rc = protoc.main(["protoc", f"-I{_HERE}", f"-I{include}", f"--python_out={_GEN}",
                      f"--grpc_python_out={_GEN}", _PROTO])
    if rc != 0:
        raise RuntimeError("protoc failed")


def _stale() -> bool:
    out = os.path.join(_GEN, "vault_pb2.py")
    return not os.path.exists(out) or os.path.getmtime(out) < os.path.getmtime(_PROTO)


os.makedirs(_GEN, exist_ok=True)
if _stale():
    _generate()
if _GEN not in sys.path:
    sys.path.insert(0, _GEN)

import vault_pb2 as pb  # noqa: E402
import vault_pb2_grpc as rpc  # noqa: E402

__all__ = ["pb", "rpc"]
