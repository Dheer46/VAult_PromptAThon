"""End-to-end check of every diagram box against the Docker Compose cluster.

  python scripts/e2e_cluster.py --endpoint http://localhost:9000 --webhook http://localhost:8080 \
      --remote http://localhost:9090 --keystone http://localhost:5000
"""
import argparse
import hashlib
import json
import os
import sys
import time
import uuid

import boto3
import httpx
from botocore.config import Config

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from vault.admin.vaultctl import Client  # noqa: E402


def s3c(ep, ak, sk):
    return boto3.client("s3", endpoint_url=ep, aws_access_key_id=ak, aws_secret_access_key=sk,
                        region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, signature_version="s3v4",
                                      request_checksum_calculation="when_required",
                                      response_checksum_validation="when_required"))


def wait(fn, t=30):
    end = time.time() + t
    while time.time() < end:
        try:
            v = fn()
            if v:
                return v
        except Exception:
            pass
        time.sleep(0.5)
    return None


def step(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}", flush=True)
    RESULTS.append(ok)


RESULTS = []


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--endpoint", default="http://localhost:9000")
    p.add_argument("--webhook", default="http://localhost:8080")
    p.add_argument("--remote", default="http://localhost:9090")
    p.add_argument("--keystone", default="http://localhost:5000")
    a = p.parse_args()
    s3 = s3c(a.endpoint, "vaultadmin", "vaultadmin-secret")
    remote = s3c(a.remote, "remote", "remote-secret")
    admin = Client(a.endpoint, "vaultadmin", "vaultadmin-secret")
    b = f"e2e-{uuid.uuid4().hex[:6]}"

    info = admin.call("GET", "info")  # arrow 1
    sets = info["storage"]["sets"]
    step("#1 admin API: cluster info", len(info["nodes"]) == 4 and all(s["online"] == 8 for s in sets),
         f"nodes={len(info['nodes'])} sets={[(s['set'], s['online']) for s in sets]} "
         f"native={all(n.get('native') for n in info['nodes'])}")

    s3.create_bucket(Bucket=b)  # arrows 2-7
    data = os.urandom(20 * 1024 * 1024 + 5)
    s3.upload_fileobj(__import__("io").BytesIO(data), b, "big.bin")
    got = s3.get_object(Bucket=b, Key="big.bin")["Body"].read()
    step("#2-#7 PUT/GET 20 MiB via LB (multipart, erasure coded)", got == data)

    s3.put_object(Bucket=b, Key="secret.txt", Body=b"top secret", ServerSideEncryption="aws:kms",
                  SSEKMSKeyId="vault-default-key")
    g = s3.get_object(Bucket=b, Key="secret.txt")
    step("#16 SSE-KMS via HashiCorp Vault Transit", g["Body"].read() == b"top secret"
         and g["ServerSideEncryption"] == "aws:kms", json.dumps(admin.call("GET", "kms/status")))

    # events (13) -> webhook + kafka
    s3.put_bucket_notification_configuration(Bucket=b, NotificationConfiguration={"QueueConfigurations": [
        {"Id": "wh", "QueueArn": "arn:vault:sqs::events:webhook", "Events": ["s3:ObjectCreated:*"]},
        {"Id": "kf", "QueueArn": "arn:vault:sqs::events:kafka", "Events": ["s3:ObjectCreated:*"]}]})
    key = f"evt-{uuid.uuid4().hex[:6]}.txt"
    s3.put_object(Bucket=b, Key=key, Body=b"event me")
    hit = wait(lambda: any(i.get("Key") == f"{b}/{key}"
                           for i in httpx.get(f"{a.webhook}/events?limit=500").json()["items"]))
    step("#13 event -> webhook target", bool(hit))
    targets = admin.call("GET", "targets")
    kafka = [t for t in targets["events"] if t["arn"].endswith(":kafka")]
    step("#13 event -> kafka target online", bool(kafka) and wait(
        lambda: [t for t in admin.call("GET", "targets")["events"] if t["arn"].endswith(":kafka")][0]["queued"] == 0,
        20) is not None, json.dumps(kafka))

    audit = wait(lambda: any(i.get("api", {}).get("object") == key and i["api"]["name"] == "PutObject"
                             for i in httpx.get(f"{a.webhook}/audit?limit=2000").json()["items"]))
    step("#14 audit entry -> webhook target", bool(audit))

    # replication (8, 11, 12)
    rb = f"rep-{uuid.uuid4().hex[:6]}"
    s3.create_bucket(Bucket=rb)
    s3.put_bucket_versioning(Bucket=rb, VersioningConfiguration={"Status": "Enabled"})
    arn = admin.call("PUT", f"replication/targets/{rb}", {"endpoint": "http://remote-s3:9000",
                     "bucket": "vault-replica", "access_key": "remote", "secret_key": "remote-secret"})["arn"]
    s3.put_bucket_replication(Bucket=rb, ReplicationConfiguration={"Role": "", "Rules": [{
        "ID": "r", "Status": "Enabled", "Priority": 1, "Filter": {"Prefix": ""},
        "DeleteMarkerReplication": {"Status": "Enabled"}, "Destination": {"Bucket": arn}}]})
    rkey = f"{rb}/photo.jpg"
    s3.put_object(Bucket=rb, Key=rkey, Body=b"replicate me")
    ok = wait(lambda: remote.get_object(Bucket="vault-replica", Key=rkey)["Body"].read() == b"replicate me")
    step("#8 #11 replication -> Remote S3", bool(ok))
    m = admin.call("GET", "replication/metrics")
    step("#12 replication metrics (all nodes)", len(m["nodes"]) == 4, json.dumps(m["total"]))

    # lifecycle tiering (15)
    admin.call("PUT", "tiers/COLD", {"type": "s3", "endpoint": "http://remote-s3:9000", "bucket": "vault-cold-tier",
                                     "prefix": f"{b}/", "access_key": "remote", "secret_key": "remote-secret"})
    s3.put_bucket_lifecycle_configuration(Bucket=b, LifecycleConfiguration={"Rules": [
        {"ID": "t", "Status": "Enabled", "Filter": {"Prefix": "big"}, "Transitions": [{"Days": 1, "StorageClass": "COLD"}]}]})
    step("#15 lifecycle rule stored (transition runs when the scanner finds it due)",
         s3.get_bucket_lifecycle_configuration(Bucket=b)["Rules"][0]["ID"] == "t")

    # keystone (17)
    body = {"auth": {"identity": {"methods": ["password"], "password": {"user": {
        "name": "demo-reader", "domain": {"name": "Default"}, "password": "reader-secret"}}},
        "scope": {"project": {"name": "demo", "domain": {"name": "Default"}}}}}
    tok = wait(lambda: httpx.post(f"{a.keystone}/v3/auth/tokens", json=body).headers.get("X-Subject-Token"), 120)
    if tok:
        r1 = httpx.get(f"{a.endpoint}/", headers={"X-Auth-Token": tok})
        r2 = httpx.put(f"{a.endpoint}/ks-{uuid.uuid4().hex[:6]}", headers={"X-Auth-Token": tok})
        step("#17 Keystone reader token: list OK, create denied", r1.status_code == 200 and r2.status_code == 403,
             f"{r1.status_code}/{r2.status_code}")
    else:
        step("#17 Keystone token", False, "keystone not reachable")

    # healing (9, 10) + scanner are exercised by tests/chaos; here: status endpoint
    step("#9 #10 healing status", "drives" in admin.call("GET", "heal/status"))
    step("metrics", "vault_erasure_set_online_drives" in httpx.get(f"{a.endpoint}/metrics").text)
    print(f"\n{sum(RESULTS)}/{len(RESULTS)} checks passed")
    sys.exit(0 if all(RESULTS) else 1)


if __name__ == "__main__":
    main()
