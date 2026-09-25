"""IAM and OIDC (diagram box): users, groups, policies, temporary credentials.

Stored as objects in `.vault.sys/iam/...` (erasure coded like everything else).
Secret keys are encrypted at rest with AES-GCM under a key derived from the
root secret. Cached in memory; reloaded on peer "reload-iam" and every 5 minutes.
Changes happen under the distributed lock `.vault.sys/iam`.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .. import errors
from ..observability.log import log
from ..storage_core.storage_api import SYS_VOL
from . import policy as pol

REFRESH_INTERVAL = 300


@dataclass
class Identity:
    access_key: str = ""
    user: str = "anonymous"
    source: str = "anonymous"  # root | local | keystone | oidc | sts | anonymous
    policies: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    project: str = ""
    session_token: str = ""
    inline_policies: list[dict] = field(default_factory=list)

    @property
    def is_root(self) -> bool:
        return self.source == "root"

    @property
    def is_anonymous(self) -> bool:
        return self.source == "anonymous"


ANONYMOUS = Identity()


class IAMSys:
    def __init__(self, settings, storage=None, ns=None, peers=None):
        self.settings = settings
        self.storage = storage
        self.ns = ns
        self.peers = peers
        self.users: dict[str, dict] = {}
        self.groups: dict[str, dict] = {}
        self.policies: dict[str, dict] = dict(pol.BUILTIN_POLICIES)
        self.sts: dict[str, dict] = {}
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"vault-iam",
                   info=b"iam-secret-encryption").derive(settings.root_password.encode())
        self._aead = AESGCM(key)
        self.loaded = False

    # ------------------------------------------------------------- crypto
    def _enc(self, secret: str) -> str:
        nonce = os.urandom(12)
        return base64.b64encode(nonce + self._aead.encrypt(nonce, secret.encode(), b"iam")).decode()

    def _dec(self, blob: str) -> str:
        raw = base64.b64decode(blob)
        return self._aead.decrypt(raw[:12], raw[12:], b"iam").decode()

    # -------------------------------------------------------------- store
    async def _put(self, path: str, doc: dict) -> None:
        await self.storage.put_object_bytes(SYS_VOL, f"iam/{path}", json.dumps(doc).encode())

    async def _del(self, path: str) -> None:
        await self.storage.delete_object(SYS_VOL, f"iam/{path}", evaluate_replication=False)

    async def load_all(self) -> None:
        if self.storage is None:
            self.loaded = True
            return
        users, groups, policies, sts = {}, {}, dict(pol.BUILTIN_POLICIES), {}
        res = await self.storage.list_objects(SYS_VOL, prefix="iam/", max_keys=1_000_000)
        for oi in res.objects:
            try:
                doc = json.loads(await self.storage.get_object_bytes(SYS_VOL, oi.key))
            except Exception as e:
                log.warning("iam entry unreadable", key=oi.key, error=str(e))
                continue
            kind, _, name = oi.key[len("iam/"):].partition("/")
            name = name.removesuffix(".json")
            {"users": users, "groups": groups, "policies": policies, "sts": sts}.get(kind, {})[name] = doc
        now = time.time()
        self.users, self.groups, self.policies = users, groups, policies
        self.sts = {k: v for k, v in sts.items() if v.get("expiry", 0) > now}
        self.loaded = True

    async def _changed(self) -> None:
        if self.peers:
            await self.peers.notify_all("reload-iam")

    async def on_reload(self, payload: bytes) -> None:
        await self.load_all()

    async def refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(REFRESH_INTERVAL)
            try:
                await self.load_all()
            except Exception as e:
                log.warning("iam refresh failed", error=str(e))

    async def _locked(self):
        return await self.ns.write(f"{SYS_VOL}/iam") if self.ns else None

    # -------------------------------------------------------------- users
    async def create_user(self, access_key: str, secret_key: str, policies: list[str] | None = None,
                          status: str = "enabled") -> dict:
        if len(access_key) < 3 or len(secret_key) < 8:
            raise errors.S3Error("InvalidArgument", "access key >= 3 chars, secret >= 8 chars")
        if access_key == self.settings.root_user:
            raise errors.S3Error("InvalidArgument", "can't redefine the root user")
        for p in policies or []:
            if p not in self.policies:
                raise errors.S3Error("InvalidArgument", f"unknown policy {p}")
        lk = await self._locked()
        try:
            doc = {"access_key": access_key, "secret": self._enc(secret_key), "status": status,
                   "policies": policies or [], "groups": [], "created": int(time.time())}
            await self._put(f"users/{access_key}.json", doc)
            self.users[access_key] = doc
        finally:
            if lk:
                await lk.release()
        await self._changed()
        return self.user_info(access_key)

    async def delete_user(self, access_key: str) -> None:
        if access_key not in self.users:
            raise errors.S3Error("InvalidArgument", f"no such user {access_key}", 404)
        await self._del(f"users/{access_key}.json")
        self.users.pop(access_key, None)
        await self._changed()

    def user_info(self, access_key: str) -> dict:
        u = self.users[access_key]
        return {"access_key": access_key, "status": u["status"], "policies": u["policies"],
                "groups": u.get("groups", [])}

    def list_users(self) -> list[dict]:
        return [self.user_info(a) for a in sorted(self.users)]

    async def set_user_status(self, access_key: str, status: str) -> None:
        u = self.users[access_key]
        u["status"] = status
        await self._put(f"users/{access_key}.json", u)
        await self._changed()

    # ----------------------------------------------------------- policies
    async def put_policy(self, name: str, doc: dict) -> None:
        pol.parse_policy(json.dumps(doc))
        await self._put(f"policies/{name}.json", doc)
        self.policies[name] = doc
        await self._changed()

    async def delete_policy(self, name: str) -> None:
        if name in pol.BUILTIN_POLICIES:
            raise errors.S3Error("InvalidArgument", "can't delete a built-in policy")
        await self._del(f"policies/{name}.json")
        self.policies.pop(name, None)
        await self._changed()

    async def attach_policy(self, policy_name: str, user: str | None = None,
                            group: str | None = None) -> None:
        if policy_name not in self.policies:
            raise errors.S3Error("InvalidArgument", f"unknown policy {policy_name}")
        if user:
            u = self.users[user]
            if policy_name not in u["policies"]:
                u["policies"].append(policy_name)
            await self._put(f"users/{user}.json", u)
        if group:
            g = self.groups.setdefault(group, {"members": [], "policies": []})
            if policy_name not in g["policies"]:
                g["policies"].append(policy_name)
            await self._put(f"groups/{group}.json", g)
        await self._changed()

    async def add_to_group(self, group: str, user: str) -> None:
        g = self.groups.setdefault(group, {"members": [], "policies": []})
        if user not in g["members"]:
            g["members"].append(user)
        u = self.users[user]
        if group not in u.setdefault("groups", []):
            u["groups"].append(group)
        await self._put(f"groups/{group}.json", g)
        await self._put(f"users/{user}.json", u)
        await self._changed()

    # ----------------------------------------------------------------- STS
    async def issue_temp_credentials(self, parent: str, source: str, policies: list[str],
                                     duration: int = 3600, project: str = "") -> dict:
        ak = "VT" + secrets.token_hex(9).upper()
        sk = secrets.token_urlsafe(30)
        token = secrets.token_urlsafe(48)
        doc = {"secret": self._enc(sk), "session_token": token, "expiry": time.time() + duration,
               "policies": policies, "parent": parent, "source": source, "project": project}
        await self._put(f"sts/{ak}.json", doc)
        self.sts[ak] = doc
        await self._changed()
        return {"AccessKeyId": ak, "SecretAccessKey": sk, "SessionToken": token,
                "Expiration": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(doc["expiry"]))}

    # ------------------------------------------------------------- lookup
    def lookup(self, access_key: str) -> tuple[str, Identity] | None:
        """SigV4 secret lookup: returns (secret_key, identity)."""
        s = self.settings
        if access_key == s.root_user:
            return s.root_password, Identity(access_key, access_key, "root", ["consoleAdmin"])
        u = self.users.get(access_key)
        if u:
            if u["status"] != "enabled":
                return None
            pols = list(u["policies"])
            for g in u.get("groups", []):
                pols += self.groups.get(g, {}).get("policies", [])
            return self._dec(u["secret"]), Identity(access_key, access_key, "local", pols,
                                                    list(u.get("groups", [])))
        t = self.sts.get(access_key)
        if t and t["expiry"] > time.time():
            return self._dec(t["secret"]), Identity(access_key, t["parent"], t.get("source", "sts"),
                                                    list(t["policies"]), project=t.get("project", ""),
                                                    session_token=t["session_token"])
        return None

    # ------------------------------------------------------- authorization
    def authorize(self, ident: Identity, action: str, bucket: str = "", key: str = "",
                  conditions: dict | None = None, bucket_policy: dict | None = None) -> bool:
        if ident.is_root:
            return True
        conditions = dict(conditions or {})
        conditions.setdefault("aws:username", ident.user)
        conditions.setdefault("aws:userid", ident.access_key)
        resource = pol.resource_arn(bucket, key)
        docs = [self.policies[p] for p in ident.policies if p in self.policies] + ident.inline_policies
        id_result = None if ident.is_anonymous else pol.evaluate(docs, action, resource, conditions)
        bp_result = None
        if bucket_policy:
            who = "*" if ident.is_anonymous else ident.access_key
            bp_result = pol.evaluate([bucket_policy], action, resource, conditions, principal=who)
        if "deny" in (id_result, bp_result):
            return False
        return "allow" in (id_result, bp_result)
