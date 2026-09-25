"""Bucket Replication (diagram box).

Arrow #8: Storage Facade -> Bucket Replication "evaluates replication" (after every
successful PUT, copy, multipart complete and delete).
Arrow #11: Bucket Replication -> Remote S3 "replicates objects" (dotted; boto3).

Tasks go to a durable queue store on a local drive before anything else happens,
so a crash never loses work; the Scanner re-queues anything still PENDING/FAILED.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import time
import uuid
from fnmatch import fnmatchcase

from .. import errors
from ..api_surface.s3_xml import parse
from ..integrations.queue_store import QueueStore
from ..observability import metrics
from ..observability.log import log
from ..storage_core.filemeta import REPL_STATUS

MULTIPART_THRESHOLD = 64 * 1024 * 1024
MAX_ATTEMPTS = 5
REPLICA_META = "vault-replication-status"  # x-amz-meta-vault-replication-status: REPLICA


def parse_replication(xml: str) -> dict:
    root = parse(xml.encode() if isinstance(xml, str) else xml)
    rules = []
    for r in root.findall("Rule"):
        f = r.find("Filter")
        prefix = r.findtext("Prefix") or ""
        tags: dict[str, str] = {}
        if f is not None:
            prefix = f.findtext("Prefix") or f.findtext("And/Prefix") or prefix
            for t in f.findall("Tag") + f.findall("And/Tag"):
                tags[t.findtext("Key") or ""] = t.findtext("Value") or ""
        dest = r.findtext("Destination/Bucket") or ""
        rules.append({
            "id": r.findtext("ID") or str(uuid.uuid4()),
            "status": r.findtext("Status") or "Enabled",
            "priority": int(r.findtext("Priority") or 0),
            "prefix": prefix, "tags": tags, "destination": dest,
            "storage_class": r.findtext("Destination/StorageClass") or "",
            "delete_marker": (r.findtext("DeleteMarkerReplication/Status") or "Disabled") == "Enabled",
            "existing": (r.findtext("ExistingObjectReplication/Status") or "Disabled") == "Enabled",
        })
    if not rules:
        raise errors.S3Error("MalformedXML", "replication configuration needs at least one Rule")
    rules.sort(key=lambda r: -r["priority"])
    return {"role": root.findtext("Role") or "", "rules": rules}


def object_tags(meta_user: dict) -> dict:
    raw = meta_user.get("x-amz-tagging", "")
    out = {}
    for pair in raw.split("&"):
        if pair:
            k, _, v = pair.partition("=")
            from urllib.parse import unquote_plus
            out[unquote_plus(k)] = unquote_plus(v)
    return out


def match_rule(cfg: dict | None, key: str, tags: dict) -> dict | None:
    if not cfg:
        return None
    for r in cfg["rules"]:
        if r["status"] != "Enabled" or not key.startswith(r["prefix"]):
            continue
        if any(tags.get(k) != v for k, v in r["tags"].items()):
            continue
        return r
    return None


class ReplicationSys:
    def __init__(self, settings, storage, bucket_meta, queue_dir: str, node: str):
        self.s = settings
        self.storage = storage
        self.bucket_meta = bucket_meta
        self.node = node
        self.store = QueueStore(os.path.join(queue_dir, "repl-queue", node))
        self.q: asyncio.Queue = asyncio.Queue()
        self.reader = None  # set by main: AppFacade.open_for_replication (decrypts SSE)
        self._clients: dict[str, object] = {}
        self.stats = {"completed": 0, "failed": 0, "in_flight": 0, "completed_bytes": 0,
                      "latency": [], "per_target": {}, "per_bucket": {}}
        self._queued: dict[str, dict] = {}  # name -> task (for backlog metrics)
        self._workers: list[asyncio.Task] = []

    # --------------------------------------------------------------- config
    def target_for(self, bm, dest: str) -> tuple[str, dict] | None:
        targets = bm.replication_targets or {}
        if dest in targets:
            return dest, targets[dest]
        name = dest.split(":::")[-1] if dest.startswith("arn:aws:s3:::") else dest
        for arn, t in targets.items():
            if t.get("bucket") == name:
                return arn, t
        return None

    def _client(self, arn: str, t: dict):
        c = self._clients.get(arn)
        if c is None:
            import boto3
            from botocore.config import Config
            c = boto3.client("s3", endpoint_url=t.get("endpoint") or None,
                             aws_access_key_id=t.get("access_key"),
                             aws_secret_access_key=t.get("secret_key"),
                             region_name=t.get("region") or "us-east-1",
                             config=Config(s3={"addressing_style": t.get("addressing_style", "path")},
                                           retries={"max_attempts": 2}, connect_timeout=5,
                                           read_timeout=60,
                                           request_checksum_calculation="when_required",
                                           response_checksum_validation="when_required"))
            self._clients[arn] = c
        return c

    # ------------------------------------------------------- evaluate (#8)
    async def evaluate(self, bucket: str, key: str, fv, op: str = "put") -> None:
        """Arrow #8 "evaluates replication"."""
        try:
            bm = await self.bucket_meta.get(bucket)
        except errors.S3Error:
            return
        cfg = bm.parsed("replication", "replication_xml", parse_replication)
        if not cfg or fv.meta_sys.get(REPL_STATUS) == "REPLICA":
            return  # never re-replicate a replica
        rule = match_rule(cfg, key, object_tags(fv.meta_user))
        if not rule:
            return
        tgt = self.target_for(bm, rule["destination"])
        if not tgt:
            log.warning("replication target not configured", bucket=bucket, dest=rule["destination"])
            return
        try:
            await self.storage.update_version_meta(bucket, key, fv.version_id,
                                                   meta_sys={REPL_STATUS: "PENDING"})
        except errors.S3Error as e:
            log.warning("could not mark PENDING", bucket=bucket, key=key, error=str(e))
        self.enqueue({"bucket": bucket, "key": key, "version_id": fv.version_id, "op": op,
                      "target": tgt[0], "size": fv.size, "enqueued": time.time(), "attempt": 0})

    async def evaluate_delete(self, bucket: str, key: str, res: dict) -> None:
        if not res.get("delete_marker") or not res.get("version_id"):
            return  # AWS doesn't replicate version-specific deletes
        try:
            bm = await self.bucket_meta.get(bucket)
        except errors.S3Error:
            return
        cfg = bm.parsed("replication", "replication_xml", parse_replication)
        rule = match_rule(cfg, key, {})
        if not rule or not rule["delete_marker"]:
            return
        tgt = self.target_for(bm, rule["destination"])
        if tgt:
            self.enqueue({"bucket": bucket, "key": key, "version_id": res["version_id"],
                          "op": "delete", "target": tgt[0], "size": 0, "enqueued": time.time(),
                          "attempt": 0})

    def enqueue(self, task: dict) -> None:
        name, _ = self.store.put(task)
        self._queued[name] = task
        self.q.put_nowait(name)
        self._update_backlog()

    # --------------------------------------------------------- workers (#11)
    def start(self) -> None:
        for name in self.store.list():  # reload durable tasks after a restart
            t = self.store.get(name)
            if t:
                self._queued[name] = t
                self.q.put_nowait(name)
        self._update_backlog()
        for _ in range(self.s.replication_workers):
            self._workers.append(asyncio.create_task(self.worker()))

    async def worker(self) -> None:
        while True:
            name = await self.q.get()
            task = self.store.get(name)
            if task is None:
                self._queued.pop(name, None)
                continue
            delay = task.get("not_before", 0) - time.time()
            if delay > 0:
                await asyncio.sleep(min(delay, 1.0))
                self.q.put_nowait(name)
                continue
            self.stats["in_flight"] += 1
            t0 = time.time()
            try:
                await self._replicate(task)  # "replicates objects"
                await self._set_status(task, "COMPLETED")
                self.store.delete(name)
                self._queued.pop(name, None)
                self.stats["completed"] += 1
                self.stats["completed_bytes"] += task.get("size", 0)
                lat = time.time() - task["enqueued"]
                self.stats["latency"] = (self.stats["latency"] + [lat])[-1000:]
                metrics.REPL_COMPLETED.labels(task["target"], task["bucket"]).inc()
                metrics.REPL_LATENCY.labels(task["target"]).observe(time.time() - t0)
            except Exception as e:
                task["attempt"] = task.get("attempt", 0) + 1
                status = "FAILED" if task["attempt"] >= MAX_ATTEMPTS else "PENDING"
                metrics.REPL_FAILED.labels(task["target"], task["bucket"]).inc()
                log.warning("replication failed", bucket=task["bucket"], key=task["key"],
                            attempt=task["attempt"], error=str(e))
                await self._set_status(task, status)
                if status == "PENDING":
                    task["not_before"] = time.time() + min(2 ** task["attempt"], 300)
                    self.store.update(name, task)
                    self._queued[name] = task
                    self.q.put_nowait(name)
                else:
                    self.stats["failed"] += 1
                    self.store.delete(name)
                    self._queued.pop(name, None)
            finally:
                self.stats["in_flight"] -= 1
                self._update_backlog()

    async def _set_status(self, task: dict, status: str) -> None:
        if task["op"] != "put":
            return
        try:
            await self.storage.update_version_meta(task["bucket"], task["key"], task["version_id"],
                                                   meta_sys={REPL_STATUS: status})
        except errors.S3Error:
            pass

    async def _replicate(self, task: dict) -> None:
        bm = await self.bucket_meta.get(task["bucket"])
        t = (bm.replication_targets or {}).get(task["target"])
        if t is None:
            raise RuntimeError(f"target {task['target']} removed")
        client = self._client(task["target"], t)
        if task["op"] == "delete":
            await asyncio.to_thread(client.delete_object, Bucket=t["bucket"], Key=task["key"])
            return
        headers, stream = await self.reader(task["bucket"], task["key"], task["version_id"])
        meta = {k[len("x-amz-meta-"):]: v for k, v in headers.items() if k.startswith("x-amz-meta-")}
        meta[REPLICA_META] = "REPLICA"
        extra = {"Metadata": meta, "ContentType": headers.get("content-type", "application/octet-stream")}
        size = int(headers.get("content-length", 0))
        if size <= MULTIPART_THRESHOLD:
            body = b"".join([c async for c in stream])
            await asyncio.to_thread(client.put_object, Bucket=t["bucket"], Key=task["key"], Body=body,
                                    ContentLength=len(body), **extra)
        else:  # multipart for > 64 MiB: spool to disk, then boto3's managed upload
            with tempfile.SpooledTemporaryFile(max_size=16 * 1024 * 1024) as f:
                async for c in stream:
                    f.write(c)
                f.seek(0)
                await asyncio.to_thread(client.upload_fileobj, f, t["bucket"], task["key"],
                                        ExtraArgs=extra)

    # --------------------------------------------------------------- stats
    def _update_backlog(self) -> None:
        per: dict[tuple, list] = {}
        for task in self._queued.values():
            k = (task["target"], task["bucket"])
            v = per.setdefault(k, [0, 0])
            v[0] += 1
            v[1] += task.get("size", 0)
        for (target, bucket), (n, b) in per.items():
            metrics.REPL_QUEUED_OBJECTS.labels(target, bucket).set(n)
            metrics.REPL_QUEUED_BYTES.labels(target, bucket).set(b)
        for target, bucket in list(self.stats["per_target"].keys()):
            if (target, bucket) not in per:
                metrics.REPL_QUEUED_OBJECTS.labels(target, bucket).set(0)
                metrics.REPL_QUEUED_BYTES.labels(target, bucket).set(0)
        self.stats["per_target"] = {k: v for k, v in per.items()}
        oldest = min((t["enqueued"] for t in self._queued.values()), default=None)
        for target in {k[0] for k in per} or {"-"}:
            metrics.REPL_LAG.labels(target).set(time.time() - oldest if oldest else 0)

    def local_stats(self) -> dict:
        lat = sorted(self.stats["latency"])

        def pct(p):
            return lat[min(len(lat) - 1, int(len(lat) * p))] if lat else 0.0
        queued = list(self._queued.values())
        return {
            "node": self.node,
            "queued_count": len(queued), "queued_bytes": sum(t.get("size", 0) for t in queued),
            "in_flight": self.stats["in_flight"], "completed": self.stats["completed"],
            "completed_bytes": self.stats["completed_bytes"], "failed": self.stats["failed"],
            "latency_p50": pct(0.5), "latency_p99": pct(0.99),
            "lag_seconds": (time.time() - min(t["enqueued"] for t in queued)) if queued else 0.0,
            "per_target": [{"target": t, "bucket": b, "queued": n, "bytes": by}
                           for (t, b), (n, by) in self.stats["per_target"].items()],
        }
