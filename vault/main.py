"""Vault node entry point: `python -m vault.main`.

Assembles every box of the architecture diagram on this node and starts the
background services (MRF, healing, scanner, replication, lifecycle journal,
metadata refresh) plus the S3 HTTP server and the Cluster RPC gRPC server.
"""
from __future__ import annotations

import asyncio
import os
import signal
import time

import uvicorn

from . import __version__
from .admin.admin_api import AdminAPI
from .api_surface.server import create_app
from .app_facade.facade import AppFacade
from .cluster_rpc.locks import LocalLocker, LockTable, NSLock
from .config import Settings, load_settings
from .integrations.audit import AuditLogger
from .integrations.events import EventNotifier
from .integrations.registry import TargetRegistry
from .integrations.replication_metrics import ReplicationMetrics
from .native import NATIVE
from .object_api.object_api import ObjectAPI
from .observability.log import log
from .ops.healing import HealingService
from .ops.replication import ReplicationSys
from .ops.scanner import ScannerService
from .security.iam import IAMSys
from .security.keystone import KeystoneClient
from .security.kms import make_kms
from .security.lifecycle import LifecycleEngine, TierManager
from .security.oidc import OIDCProvider
from .storage_core.disk_store import DiskStore
from .storage_core.erasure_set import ErasureSet
from .storage_core.format import choose_set_size, load_or_format
from .storage_core.metadata_sys import BucketMetadataSys
from .storage_core.server_pools import ServerPool, ServerPools
from .storage_core.storage_api import SYS_VOL
from .storage_core.storage_facade import StorageFacade


class VaultNode:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or load_settings()
        self.ready = False
        self.started = time.time()
        self.tasks: list[asyncio.Task] = []
        self.grpc_server = None
        self.peers = None
        self.keystone = None
        self.oidc = None
        self.audit = None
        self.scanner = None
        self.layout = None

    # ------------------------------------------------------------ bootstrap
    async def start(self) -> None:
        s = self.settings
        endpoints = s.endpoints()
        me = s.node_name if s.distributed else (endpoints[0][0] if endpoints else s.node_name)
        hosts = sorted({h for h, _, _ in endpoints})
        self.local_drives: dict[str, DiskStore] = {}
        self.lock_table = LockTable()
        drives = []
        clients = {}
        if s.distributed:
            from .cluster_rpc.remote_disk import NodeClient, PeerClient, RemoteDisk, RemoteLocker
            from .cluster_rpc.peers import Peers
            from .cluster_rpc.server import PeerServicer, start_server
            for h in hosts:
                if h != me:
                    clients[h] = NodeClient(f"{h}:{s.grpc_port}", me, s.cluster_secret)
        for host, path, ep in endpoints:
            if host == me or not s.distributed:
                d = DiskStore(path, ep)
                d.clean_tmp()
                self.local_drives[path] = d
                drives.append(d)
            else:
                drives.append(RemoteDisk(clients[host], path, ep))
        if not self.local_drives:
            raise SystemExit(f"node {me!r} has no drives; check VAULT_NODES/VAULT_NODE_NAME")
        first_local = next(iter(self.local_drives.values())).root
        if not s.queue_dir or s.queue_dir == "/var/lib/vault/queues" and os.name == "nt":
            s.queue_dir = os.path.join(first_local, SYS_VOL, "queues")
        lockers = [LocalLocker(self.lock_table, me)]
        if s.distributed:
            self.peer_servicer = PeerServicer(me)
            self.grpc_server = await start_server(s.grpc_port, self.local_drives, self.lock_table,
                                                  self.peer_servicer, s.cluster_secret)
            lockers += [RemoteLocker(c) for c in clients.values()]
            self.peers = Peers([PeerClient(c, h) for h, c in clients.items()])
            log.info("cluster rpc listening", port=s.grpc_port, peers=list(clients))
        self.ns = NSLock(lockers, owner=me)
        self.tasks.append(asyncio.create_task(self.lock_table.cleanup_loop()))

        set_size = choose_set_size(len(drives), s.set_size)
        parity = min(s.default_parity, set_size // 2)
        self.layout, heal_slots = await load_or_format(drives, set_size, parity,
                                                       i_am_formatter=(me == hosts[0]))
        parity = self.layout.get("parity", parity)
        sets = [ErasureSet(i, drives[i * set_size:(i + 1) * set_size], parity, self.ns, pool=0)
                for i in range(len(drives) // set_size)]
        self.storage = StorageFacade(ServerPools([ServerPool(0, sets, self.layout["deployment_id"])]))
        log.info("storage ready", sets=len(sets), set_size=set_size, ec=f"{set_size - parity}+{parity}",
                 native=NATIVE, node=me)

        # --- metadata, security
        self.bucket_meta = BucketMetadataSys(self.storage, self.peers, self.ns)
        self.iam = IAMSys(s, self.storage, self.ns, self.peers)
        self.kms = make_kms(s)
        self.keystone = KeystoneClient(s) if s.keystone_url else None
        self.oidc = OIDCProvider(s, self.iam) if s.oidc_jwks_url else None
        await self._retry(self.bucket_meta.load_all, "bucket metadata")
        await self._retry(self.iam.load_all, "iam")

        # --- integrations
        self.targets = TargetRegistry(s, self.storage, self.peers)
        await self._retry(self.targets.load, "targets")
        public = s.public_url or f"http://{me}:{s.s3_port}"
        self.events = EventNotifier(s, self.bucket_meta, self.targets, public)
        self.audit = AuditLogger(self.targets, me)
        self.tiers = TierManager(self.storage)
        await self._retry(self.tiers.load, "tiers")
        sysdir = os.path.join(first_local, SYS_VOL)
        self.lifecycle = LifecycleEngine(s, self.storage, self.bucket_meta, self.tiers, sysdir, self.events)
        self.replication = ReplicationSys(s, self.storage, self.bucket_meta, sysdir, me)
        self.storage.replication = self.replication  # arrow #8
        self.replication_metrics = ReplicationMetrics(self.replication, self.peers)  # arrow #12

        # --- application
        self.object_api = ObjectAPI(s)
        self.app_facade = AppFacade(s, self.storage, self.bucket_meta, self.object_api, self.iam,
                                    self.kms, self.events, self.tiers, self.lifecycle)
        self.replication.reader = self.app_facade.open_for_replication

        # --- operations
        self.healing = HealingService(self.storage, self.bucket_meta, self.layout)
        self.scanner = ScannerService(s, self.storage, self.bucket_meta, self.healing, self.lifecycle,
                                      self.replication, me)
        self.admin_api = AdminAPI(self)
        self.node_name = me

        if s.distributed:
            ps = self.peer_servicer
            ps.handlers["reload-bucket-meta"] = self.bucket_meta.on_reload
            ps.handlers["reload-iam"] = self.iam.on_reload
            ps.handlers["reload-targets"] = self.targets.reload
            ps.handlers["reload-tiers"] = lambda _p: self.tiers.load()
            ps.server_info = self.server_info
            ps.replication_stats = self._repl_stats

        spawn = lambda coro: self.tasks.append(asyncio.create_task(coro))  # noqa: E731
        spawn(self.storage.mrf_worker())
        for _ in range(2):
            spawn(self.healing.worker())
        spawn(self.healing.monitor_drives())
        spawn(self.scanner.run())
        spawn(self.lifecycle.journal_worker())
        spawn(self.bucket_meta.refresh_loop())
        spawn(self.iam.refresh_loop())
        self.replication.start()
        for slot in heal_slots:
            si, pos = divmod(slot, set_size)
            self.healing.start_drive_heal(sets[si], pos, sets[si].drives[pos], reason="replaced at startup")
        self.ready = True

    async def _retry(self, fn, what: str, attempts: int = 30) -> None:
        for i in range(attempts):
            try:
                return await fn()
            except Exception as e:
                if i == attempts - 1:
                    raise
                log.info("waiting to load", what=what, error=str(e))
                await asyncio.sleep(1)

    async def _repl_stats(self) -> dict:
        return self.replication.local_stats()

    async def server_info(self) -> dict:
        drives = []
        for path, d in self.local_drives.items():
            try:
                drives.append(await d.disk_info())
            except Exception as e:
                drives.append({"endpoint": d.endpoint, "online": False, "error": type(e).__name__})
        return {"node": self.node_name, "state": "online", "version": __version__, "native": NATIVE,
                "uptime": round(time.time() - self.started), "drives": drives,
                "scanner": self.scanner.info() if self.scanner else {},
                "healing": {k: v for k, v in self.healing.info().items() if k != "recent"}}

    async def usage(self) -> dict:
        infos = [await self.server_info()] + (await self.peers.server_infos() if self.peers else [])
        total: dict[str, dict] = {}
        for info in infos:
            for b, u in (info.get("scanner", {}).get("usage") or {}).items():
                t = total.setdefault(b, {k: 0 for k in ("objects", "versions", "delete_markers", "bytes",
                                                        "replication_pending", "replication_failed")})
                for k in t:
                    t[k] += u.get(k, 0)
        return {"buckets": total, "nodes": len(infos)}

    async def stop(self) -> None:
        tasks = list(self.tasks) + list(getattr(getattr(self, "replication", None), "_workers", []))
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for t in list(getattr(getattr(self, "targets", None), "events", {}).values()) +                 list(getattr(getattr(self, "targets", None), "audit", {}).values()):
            await t.close()
        if self.grpc_server:
            await self.grpc_server.stop(1)


async def serve(settings: Settings | None = None) -> None:
    node = VaultNode(settings)
    await node.start()
    app = create_app(node)
    config = uvicorn.Config(app, host="0.0.0.0", port=node.settings.s3_port, log_level="warning",
                            lifespan="off", timeout_keep_alive=30)
    server = uvicorn.Server(config)
    log.info("s3 api listening", port=node.settings.s3_port)
    loop = asyncio.get_running_loop()
    try:
        loop.add_signal_handler(signal.SIGTERM, lambda: setattr(server, "should_exit", True))
    except (NotImplementedError, RuntimeError):
        pass
    try:
        await server.serve()
    finally:
        await node.stop()


def main() -> None:
    try:
        import uvloop  # noqa: F401
        uvloop.install()
    except ImportError:
        pass
    asyncio.run(serve())


if __name__ == "__main__":
    main()
