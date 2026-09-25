"""Registry of configured Event Targets and Audit Targets.

Targets come from settings (env/YAML) plus admin-API definitions persisted in
`.vault.sys/config/targets.json` (PUT /vault/admin/v1/targets/{kind}/{name})."""
from __future__ import annotations

import json

from .. import errors
from ..observability.log import log
from ..storage_core.storage_api import SYS_VOL
from .targets import Target, make_target

CONFIG_KEY = "config/targets.json"


def target_arn(kind: str, name: str) -> str:
    return f"arn:vault:sqs::{name}:{kind}"


class TargetRegistry:
    def __init__(self, settings, storage=None, peers=None):
        self.settings = settings
        self.storage = storage
        self.peers = peers
        self.events: dict[str, Target] = {}  # arn -> target
        self.audit: dict[str, Target] = {}  # id -> target
        self._defs: list[dict] = []

    def _add(self, role: str, cfg: dict) -> None:
        t = make_target({k: v for k, v in cfg.items() if k != "role"}, self.settings.queue_dir + f"/{role}")
        if role == "events":
            old = self.events.pop(target_arn(t.kind, t.name), None)
            self.events[target_arn(t.kind, t.name)] = t
        else:
            old = self.audit.pop(t.id, None)
            self.audit[t.id] = t
        if old:
            try:
                import asyncio
                asyncio.get_running_loop().create_task(old.close())
            except RuntimeError:
                pass
        t.start()

    async def load(self) -> None:
        for cfg in self.settings.event_targets:
            self._add("events", cfg)
        for cfg in self.settings.audit_targets:
            self._add("audit", cfg)
        await self.reload()

    async def reload(self, payload: bytes = b"") -> None:
        if self.storage is None:
            return
        try:
            raw = await self.storage.get_object_bytes(SYS_VOL, CONFIG_KEY)
            self._defs = json.loads(raw)
        except errors.S3Error:
            self._defs = []
        for cfg in self._defs:
            try:
                self._add(cfg.get("role", "events"), cfg)
            except Exception as e:
                log.warning("bad target definition", cfg=cfg.get("name"), error=str(e))

    async def define(self, role: str, cfg: dict) -> str:
        if role not in ("events", "audit"):
            raise errors.S3Error("InvalidArgument", "role must be events or audit")
        cfg = {**cfg, "role": role}
        try:
            self._add(role, cfg)
        except (TypeError, ValueError) as e:
            raise errors.S3Error("InvalidArgument", str(e))
        self._defs = [d for d in self._defs
                      if not (d.get("name") == cfg["name"] and d.get("type") == cfg["type"]
                              and d.get("role") == role)] + [cfg]
        await self.storage.put_object_bytes(SYS_VOL, CONFIG_KEY, json.dumps(self._defs).encode())
        if self.peers:
            await self.peers.notify_all("reload-targets")
        return target_arn(cfg["type"], cfg["name"])

    def info(self) -> dict:
        return {"events": [{"arn": a, **t.info()} for a, t in self.events.items()],
                "audit": [t.info() for t in self.audit.values()]}
