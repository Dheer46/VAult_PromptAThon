"""Encryption KMS (diagram box) — arrow #16: Encryption KMS -> KMS Provider
"requests keys" (dotted, HTTP to HashiCorp Vault Transit).

Envelope encryption: for each object ask the provider for a data key (DEK). It
returns the DEK in plaintext and sealed under a master key that never leaves the
KMS. The object is encrypted with the plaintext DEK, which is then discarded;
only the sealed DEK is stored in xl.meta. The DEK is bound to the object through
the KMS encryption context, so a sealed key copied onto another object can't be
unsealed.

Naming: "Vault" is this project; the external KMS Provider is always called
`kms_provider` / HashiCorp Vault here.
"""
from __future__ import annotations

import base64
import json
import os
import time

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .. import errors
from ..observability import metrics
from ..observability.log import log


def _ctx(context: dict) -> str:
    return base64.b64encode(json.dumps(context, sort_keys=True, separators=(",", ":")).encode()).decode()


class HashiCorpTransitKMS:
    """KMS Provider client: HashiCorp Vault's Transit secrets engine."""

    name = "hashicorp-vault-transit"

    def __init__(self, addr: str, token: str, default_key: str):
        self.addr = addr.rstrip("/")
        self.default_key = default_key
        self._http = httpx.AsyncClient(timeout=5.0, headers={"X-Vault-Token": token})
        self._fails = 0
        self._open_until = 0.0

    async def _post(self, op: str, path: str, body: dict) -> dict:
        metrics.KMS_REQUESTS.labels(op).inc()
        if time.monotonic() < self._open_until:
            metrics.KMS_ERRORS.labels(op).inc()
            raise errors.S3Error("KMSUnavailable", "KMS provider unavailable (circuit open)", 503)
        last = None
        for attempt in range(3):  # retry with backoff
            try:
                r = await self._http.post(f"{self.addr}/v1/{path}", json=body)
                if r.status_code >= 500:
                    raise httpx.HTTPStatusError("server error", request=r.request, response=r)
                if r.status_code >= 400:
                    metrics.KMS_ERRORS.labels(op).inc()
                    raise errors.S3Error("AccessDenied" if r.status_code == 403 else "InvalidArgument",
                                         f"KMS {op}: {r.text[:200]}")
                self._fails = 0
                return r.json().get("data") or {}
            except httpx.HTTPError as e:
                last = e
                await _sleep(0.1 * (2 ** attempt))
        self._fails += 1
        if self._fails >= 3:
            self._open_until = time.monotonic() + 5
        metrics.KMS_ERRORS.labels(op).inc()
        log.warning("kms provider unreachable", error=str(last))
        raise errors.S3Error("KMSUnavailable", "KMS provider unavailable", 503)

    async def generate_key(self, key_id: str, context: dict) -> tuple[bytes, str]:
        d = await self._post("datakey", f"transit/datakey/plaintext/{key_id}",
                             {"context": _ctx(context), "bits": 256})
        return base64.b64decode(d["plaintext"]), d["ciphertext"]

    async def decrypt_key(self, key_id: str, sealed: str, context: dict) -> bytes:
        d = await self._post("decrypt", f"transit/decrypt/{key_id}",
                             {"ciphertext": sealed, "context": _ctx(context)})
        return base64.b64decode(d["plaintext"])

    async def create_key(self, key_id: str) -> None:
        await self._post("create", f"transit/keys/{key_id}", {"derived": True})

    async def status(self) -> dict:
        try:
            r = await self._http.get(f"{self.addr}/v1/sys/health")
            return {"provider": self.name, "online": r.status_code == 200, "addr": self.addr}
        except httpx.HTTPError as e:
            return {"provider": self.name, "online": False, "error": str(e)}


class BuiltinKMS:
    """Development-only KMS: a master key derived from the root secret. Used when no
    KMS Provider is configured so SSE can be exercised on a laptop. Not for production."""

    name = "builtin"

    def __init__(self, root_secret: str, default_key: str):
        self.default_key = default_key
        self._root = root_secret.encode()
        log.warning("using the builtin development KMS; configure VAULT_KMS_ADDR for HashiCorp Vault")

    def _master(self, key_id: str, context: dict) -> AESGCM:
        info = f"{key_id}|{json.dumps(context, sort_keys=True)}".encode()
        return AESGCM(HKDF(algorithm=hashes.SHA256(), length=32, salt=b"vault-kms", info=info)
                      .derive(self._root))

    async def generate_key(self, key_id: str, context: dict) -> tuple[bytes, str]:
        metrics.KMS_REQUESTS.labels("datakey").inc()
        dek = os.urandom(32)
        nonce = os.urandom(12)
        sealed = nonce + self._master(key_id, context).encrypt(nonce, dek, b"dek")
        return dek, "builtin:v1:" + base64.b64encode(sealed).decode()

    async def decrypt_key(self, key_id: str, sealed: str, context: dict) -> bytes:
        metrics.KMS_REQUESTS.labels("decrypt").inc()
        raw = base64.b64decode(sealed.removeprefix("builtin:v1:"))
        try:
            return self._master(key_id, context).decrypt(raw[:12], raw[12:], b"dek")
        except Exception:
            raise errors.S3Error("AccessDenied", "sealed key does not belong to this object")

    async def create_key(self, key_id: str) -> None:
        return None

    async def status(self) -> dict:
        return {"provider": self.name, "online": True}


async def _sleep(s: float) -> None:
    import asyncio
    await asyncio.sleep(s)


def make_kms(settings):
    if settings.kms_addr:
        return HashiCorpTransitKMS(settings.kms_addr, settings.kms_token, settings.kms_default_key)
    return BuiltinKMS(settings.root_password, settings.kms_default_key)
