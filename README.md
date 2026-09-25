# Vault — fault-tolerant, S3-compatible distributed object storage (Python + C++)

Vault splits every object into data + parity shards (Reed-Solomon, EC 5+3 by default),
spreads them over many drives on many machines, and keeps working when drives or whole
machines die. Background services detect and rebuild what was lost. Any S3 client
(boto3, AWS CLI, SDKs) talks to it unchanged.

- **C++ (`native/`)**: Intel ISA-L erasure coding + BLAKE3 bitrot hashing, exposed to Python
  as `vault_native` via pybind11, with the GIL released during heavy work.
- **Python (`vault/`)**: everything else: HTTP API, Cluster RPC (gRPC), metadata, healing,
  scanner, IAM, KMS, replication, lifecycle, events, audit.

When the native module isn't compiled (e.g. a Windows laptop), `vault/storage_core/rs_py.py`
provides a numpy Reed-Solomon that produces **byte-identical** shards (same ISA-L Cauchy matrix,
GF(2^8)/0x11d), so the same data works either way.

## The diagram, box by box

| Group | Box | Code |
|---|---|---|
| Actors | Administrator | `vault/admin/admin_api.py` + `vaultctl` CLI (`vault/admin/vaultctl.py`) |
| Actors | Storage Client | any S3 client (boto3, `aws` CLI) |
| Client and API | API Surface | `vault/api_surface/server.py`, `router.py`, `sigv4.py`, `s3_xml.py` |
| Client and API | Application Facade | `vault/app_facade/facade.py` |
| Client and API | Object API | `vault/object_api/object_api.py`, `multipart.py` |
| Storage Core | Storage Facade | `vault/storage_core/storage_facade.py`, `erasure_set.py`, `server_pools.py` |
| Storage Core | Bucket Metadata | `vault/storage_core/metadata_sys.py` (stored in hidden bucket `.vault.sys`) |
| Storage Core | Object Metadata | `vault/storage_core/filemeta.py` (`xl.meta` next to the shards on every drive) |
| Storage Core | Erasure Coding | `native/src/erasure.cpp` + `vault/storage_core/erasure.py` |
| Storage Core | Disk Storage | `vault/storage_core/disk_store.py` + `native/src/bitrot.cpp` |
| Distributed Operations | Scanner Service | `vault/ops/scanner.py` |
| Distributed Operations | Healing Service | `vault/ops/healing.py` (+ MRF queue in the Storage Facade) |
| Distributed Operations | Cluster RPC | `vault/cluster_rpc/` (`vault.proto`, `server.py`, `remote_disk.py`, `locks.py`) |
| Distributed Operations | Bucket Replication | `vault/ops/replication.py` |
| Security and Governance | Lifecycle Engine | `vault/security/lifecycle.py` |
| Security and Governance | Encryption KMS | `vault/security/kms.py`, `sse.py` |
| Security and Governance | IAM and OIDC | `vault/security/iam.py`, `policy.py`, `keystone.py`, `oidc.py` |
| External Integrations | Event Notifications | `vault/integrations/events.py` |
| External Integrations | Replication Metrics | `vault/integrations/replication_metrics.py` |
| External Integrations | Audit Pipeline | `vault/integrations/audit.py` (shared pipeline: `queue_store.py`, `targets/`) |
| Outside | Event Targets | webhook receiver + Kafka (Redpanda) |
| Outside | Audit Targets | webhook receiver / Kafka / JSONL file |
| Outside | Remote S3 | a separate single-node S3 server locally, a real AWS S3 bucket on EC2 |
| Outside | KMS Provider | HashiCorp Vault, Transit engine |
| Outside | Keystone Service | OpenStack Keystone (+ MariaDB) |

## Every arrow

| # | From → To | Label | Where |
|---|---|---|---|
| 1 | Administrator → API Surface | administers | `vaultctl` → `/vault/admin/v1/*` (`AdminAPI`) |
| 2 | Storage Client → API Surface | sends requests | SigV4-signed S3 HTTP → `server.s3_entry` |
| 3 | API Surface → Application Facade | enters application | `S3Router` handlers call `AppFacade.*` |
| 4 | Application Facade → Storage Facade | delegates storage | `AppFacade` → `StorageFacade.put_object(...)` etc. |
| 5 | Application Facade → Bucket Metadata | reads config | `BucketMetadataSys.get(bucket)` |
| 6 | Object API → Object Metadata | handles metadata | `ObjectAPI` builds/reads `FileVersion` fields |
| 7 | Storage Facade → Disk Storage | delegates disk I/O | `ErasureSet` → `DiskStore` / `RemoteDisk` |
| 8 | Storage Facade → Bucket Replication | evaluates replication | `ReplicationSys.evaluate()` after PUT/copy/complete/delete |
| 9 | Healing → Disk Storage | checks disks | `HealingService.check_drives_once()` → `disk_info()` every 10 s |
| 10 | Healing → Storage Facade | repairs storage | `StorageFacade.heal_object()` |
| 11 | Bucket Replication → Remote S3 | replicates objects (dotted) | replication workers → boto3 `put_object` |
| 12 | Replication Metrics → Bucket Replication | observes backlog | `ReplicationMetrics.snapshot()` (+ peers) |
| 13 | Event Notifications → Event Targets | publishes events | `EventNotifier` → webhook / Kafka targets |
| 14 | Audit Pipeline → Audit Targets | dispatches entries | `AuditLogger` → webhook / Kafka / file |
| 15 | Lifecycle Engine → Remote S3 | tiers objects (dotted) | `LifecycleEngine.transition()` → boto3 |
| 16 | Encryption KMS → KMS Provider | requests keys (dotted) | Transit `datakey` / `decrypt` |
| 17 | IAM and OIDC → Keystone Service | authenticates users (dotted) | `GET /v3/auth/tokens`, `POST /v3/ec2tokens` |

The diagram doesn't draw these calls, but they exist too: API Surface → IAM (every request),
Application Facade → KMS (encrypt on PUT, decrypt on GET), Application Facade → Events/Audit,
Storage Facade/Healing/Scanner → Erasure Coding and Cluster RPC, Scanner → Healing/Lifecycle/Replication.

## Design in one paragraph

No separate metadata cluster: object metadata is an `xl.meta` file next to the shards on
every drive (written with the same quorum rules as data), and bucket metadata is an object
in the hidden, erasure-coded `.vault.sys` bucket. Consistency for concurrent writes comes
from distributed locks (a majority of nodes must grant) plus quorum reads/writes: read quorum
`k`, write quorum `k` (`k+1` when `k == m`). Writes go to `tmp`, are fsynced, then
atomically renamed into place; readers see the old or the new version, never a partial one.
Every shard block carries a BLAKE3 hash; a mismatch makes that shard "missing" and queues a heal.

## Quick start

### Full cluster (every box in the diagram) with Docker Compose

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```

```bash
aws --endpoint-url http://localhost:9000 s3 mb s3://photos
```

| Service | URL | Credentials |
|---|---|---|
| S3 (HAProxy → node1..4, health-checked every 1 s) | http://localhost:9000 | `vaultadmin` / `vaultadmin-secret` |
| **Web console** | http://localhost:9000/vault/console | any access key + secret (root: `vaultadmin` / `vaultadmin-secret`) |
| Grafana | http://localhost:3000 | anonymous admin |
| Prometheus | http://localhost:9095 | |
| HashiCorp Vault (KMS) | http://localhost:8200 | token `root` |
| Keystone | http://localhost:5000/v3 | `admin` / `admin-secret`, `demo` / `demo-secret` |
| Remote S3 (stand-in S3 server) | http://localhost:9090 | `remote` / `remote-secret` |
| Webhook receiver | http://localhost:8080/events, /audit | |

If a host port is already taken, override it, e.g.
`VAULT_S3_PORT=9900 GRAFANA_PORT=3300 WEBHOOK_PORT=8088 NODE1_PORT=9901 ... docker compose ... up -d`.
Check every box end to end with
`python scripts/e2e_cluster.py --endpoint http://localhost:9000 --webhook http://localhost:8080`.

4 nodes × 4 drives = 16 drives = 2 erasure sets of 8 (EC 5+3). Each set takes 2 drives from
each node, so losing a whole node removes only 2 drives from each set.

Wire up replication, tiering and events (all through the admin API):

```bash
export VAULT_ENDPOINT=http://localhost:9000
python -m vault.admin.vaultctl replication target photos --endpoint http://remote-s3:9000 \
  --bucket vault-replica --access-key remote --secret-key remote-secret
python -m vault.admin.vaultctl tier add COLD --endpoint http://remote-s3:9000 --bucket vault-cold-tier \
  --access-key remote --secret-key remote-secret
python -m vault.admin.vaultctl user add alice alice-secret-key --policy readonly
```

Event targets are pre-configured from the environment: `arn:vault:sqs::events:webhook` and
`arn:vault:sqs::events:kafka` (use them in `PutBucketNotificationConfiguration`). Audit entries
go to the webhook receiver, Kafka topic `vault-audit` and `/var/log/vault/audit.jsonl`.

### Single node on a laptop (no Docker)

```bash
pip install -e ".[test]" --no-build-isolation   # builds the C++ core if a compiler + ISA-L exist
VAULT_DRIVES="./data/disk{1...8}" python -m vault.main
```

Without a KMS Provider configured, a clearly-labelled development KMS is used so SSE can be tried.

## Tests

```bash
python -m pytest tests/unit tests/component tests/integration
```

- `tests/unit`: erasure math (hypothesis property tests, ISA-L compatibility), `xl.meta` + quorum
  resolver, SigV4 against botocore's signer (incl. presigned + aws-chunked), policies, SSE, lifecycle, locks.
- `tests/component`: 8-drive erasure set under failure (lose 3 drives OK / 4 fails, bitrot,
  drive dies mid-PUT, 50 concurrent writers, stale-drive deletes, crash before rename, path traversal);
  4 gRPC "nodes" in one process (remote drives, lock exclusivity, lock quorum loss, circuit breaker, auth).
- `tests/integration`: boto3 against a live node (buckets, objects, ranges, listing/pagination, multipart,
  copy, versioning, presigned URLs, SSE-S3/KMS/C, tagging, bucket policies, IAM users, notifications,
  health/metrics); replication and lifecycle tiering into a second Vault acting as Remote S3; wiped-drive
  heal; deep-scan bitrot repair.
- `tests/chaos`: the correctness checker and 12 chaos scenarios against the Compose cluster:
  `python tests/chaos/chaos.py list`.

## AWS EC2

`deploy/aws/provision.sh` builds the budget layout (4 storage nodes × 4 gp3 volumes + 1 services node,
real S3 buckets in a second region for replication and tiering); `run-node.sh` starts a node;
`services-compose.yml` runs the external services; `teardown.sh` terminates the instances.
Set an AWS Budgets alert first — inter-region traffic is billed per GB.
