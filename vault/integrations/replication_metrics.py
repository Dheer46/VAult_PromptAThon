"""Replication Metrics (diagram box) — arrow #12: Replication Metrics -> Bucket
Replication "observes backlog". Aggregates this node's queue stats with every
peer's (Peer.ReplicationStats). Exposed at GET /vault/admin/v1/replication/metrics
and through Prometheus gauges maintained by ReplicationSys."""
from __future__ import annotations


class ReplicationMetrics:
    def __init__(self, replication_sys, peers=None):
        self.repl = replication_sys
        self.peers = peers

    async def snapshot(self) -> dict:  # "observes backlog"
        nodes = [self.repl.local_stats()]
        if self.peers:
            nodes += await self.peers.replication_stats()  # other nodes
        total = {k: sum(n.get(k, 0) for n in nodes)
                 for k in ("queued_count", "queued_bytes", "in_flight", "completed",
                           "completed_bytes", "failed")}
        total["lag_seconds"] = max((n.get("lag_seconds", 0) for n in nodes), default=0)
        total["latency_p99"] = max((n.get("latency_p99", 0) for n in nodes), default=0)
        return {"total": total, "nodes": nodes}
