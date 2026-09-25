"""vaultctl — the Administrator's CLI (arrow #1 "administers").

Signs requests to /vault/admin/v1/* with SigV4 using botocore (no need to
reimplement client-side signing).

  vaultctl info
  vaultctl user add alice alice-secret-key --policy readonly
  vaultctl policy put photos-rw policy.json && vaultctl policy attach photos-rw --user alice
  vaultctl heal photos [prefix] [--deep]
  vaultctl replication target photos --endpoint https://s3.ap-south-1.amazonaws.com \
      --bucket vault-replica-photos --access-key AK --secret-key SK --region ap-south-1
  vaultctl tier add COLD --endpoint http://remote-s3:9000 --bucket vault-cold-tier \
      --access-key remote --secret-key remote-secret
  vaultctl target add webhook thumbs --url http://webhook:8080/events [--role audit]
  vaultctl kms key create my-key
Environment: VAULT_ENDPOINT (default http://localhost:9000), VAULT_ACCESS_KEY, VAULT_SECRET_KEY.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse

import httpx
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials


class Client:
    def __init__(self, endpoint: str, ak: str, sk: str, region: str = "us-east-1"):
        self.endpoint = endpoint.rstrip("/")
        self.creds = Credentials(ak, sk)
        self.region = region

    def call(self, method: str, path: str, body: dict | None = None, query: dict | None = None):
        url = f"{self.endpoint}/vault/admin/v1/{path.lstrip('/')}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode() if body is not None else b""
        req = AWSRequest(method=method, url=url, data=data, headers={"content-type": "application/json"})
        S3SigV4Auth(self.creds, "s3", self.region).add_auth(req)
        r = httpx.request(method, url, content=data, headers=dict(req.headers), timeout=600)
        try:
            out = r.json()
        except ValueError:
            out = {"status": r.status_code, "body": r.text}
        if r.status_code >= 400:
            print(json.dumps(out, indent=2), file=sys.stderr)
            sys.exit(1)
        return out


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="vaultctl", description="Vault admin CLI")
    p.add_argument("--endpoint", default=os.environ.get("VAULT_ENDPOINT", "http://localhost:9000"))
    p.add_argument("--access-key", default=os.environ.get("VAULT_ACCESS_KEY", "vaultadmin"))
    p.add_argument("--secret-key", default=os.environ.get("VAULT_SECRET_KEY", "vaultadmin-secret"))
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("info")
    sub.add_parser("usage")
    sub.add_parser("scanner")
    sub.add_parser("locks")

    u = sub.add_parser("user").add_subparsers(dest="action", required=True)
    ua = u.add_parser("add")
    ua.add_argument("access_key")
    ua.add_argument("secret_key")
    ua.add_argument("--policy", action="append", default=[])
    ur = u.add_parser("remove")
    ur.add_argument("access_key")
    u.add_parser("list")
    us = u.add_parser("disable")
    us.add_argument("access_key")
    ue = u.add_parser("enable")
    ue.add_argument("access_key")

    pol = sub.add_parser("policy").add_subparsers(dest="action", required=True)
    pp = pol.add_parser("put")
    pp.add_argument("name")
    pp.add_argument("file")
    pol.add_parser("list")
    pa = pol.add_parser("attach")
    pa.add_argument("name")
    pa.add_argument("--user")
    pa.add_argument("--group")
    pr = pol.add_parser("remove")
    pr.add_argument("name")

    g = sub.add_parser("group").add_subparsers(dest="action", required=True)
    ga = g.add_parser("add-member")
    ga.add_argument("group")
    ga.add_argument("user")

    h = sub.add_parser("heal")
    h.add_argument("bucket", nargs="?")
    h.add_argument("prefix", nargs="?", default="")
    h.add_argument("--deep", action="store_true")
    h.add_argument("--status", action="store_true")

    r = sub.add_parser("replication").add_subparsers(dest="action", required=True)
    r.add_parser("metrics")
    rt = r.add_parser("target")
    rt.add_argument("source_bucket")
    for f in ("endpoint", "bucket", "access-key", "secret-key"):
        rt.add_argument(f"--{f}", required=True)
    rt.add_argument("--region", default="us-east-1")

    t = sub.add_parser("tier").add_subparsers(dest="action", required=True)
    ta = t.add_parser("add")
    ta.add_argument("name")
    for f in ("endpoint", "bucket", "access-key", "secret-key"):
        ta.add_argument(f"--{f}", required=f != "endpoint")
    ta.add_argument("--prefix", default="")
    ta.add_argument("--region", default="us-east-1")
    t.add_parser("list")

    tg = sub.add_parser("target").add_subparsers(dest="action", required=True)
    tga = tg.add_parser("add")
    tga.add_argument("kind", choices=["webhook", "kafka", "file"])
    tga.add_argument("name")
    tga.add_argument("--role", choices=["events", "audit"], default="events")
    tga.add_argument("--url")
    tga.add_argument("--brokers")
    tga.add_argument("--topic")
    tga.add_argument("--path")
    tga.add_argument("--auth-token")
    tg.add_parser("list")

    k = sub.add_parser("kms").add_subparsers(dest="action", required=True)
    k.add_parser("status")
    kk = k.add_parser("key")
    kk.add_argument("op", choices=["create"])
    kk.add_argument("name")

    a = p.parse_args(argv)
    c = Client(a.endpoint, a.access_key, a.secret_key)
    out = None
    if a.cmd in ("info", "usage", "scanner", "locks"):
        out = c.call("GET", a.cmd)
    elif a.cmd == "user":
        if a.action == "add":
            out = c.call("PUT", f"users/{a.access_key}", {"secret_key": a.secret_key, "policies": a.policy})
        elif a.action == "remove":
            out = c.call("DELETE", f"users/{a.access_key}")
        elif a.action == "list":
            out = c.call("GET", "users")
        else:
            out = c.call("POST", f"users/{a.access_key}/status",
                         {"status": "enabled" if a.action == "enable" else "disabled"})
    elif a.cmd == "policy":
        if a.action == "put":
            with open(a.file) as f:
                out = c.call("PUT", f"policies/{a.name}", json.load(f))
        elif a.action == "list":
            out = c.call("GET", "policies")
        elif a.action == "attach":
            out = c.call("POST", "attach", {"policy": a.name, "user": a.user, "group": a.group})
        else:
            out = c.call("DELETE", f"policies/{a.name}")
    elif a.cmd == "group":
        out = c.call("POST", f"groups/{a.group}/members", {"user": a.user})
    elif a.cmd == "heal":
        if a.status or not a.bucket:
            out = c.call("GET", "heal/status")
        else:
            out = c.call("POST", f"heal/{a.bucket}/{a.prefix}".rstrip("/"),
                         query={"deep": "true"} if a.deep else None)
    elif a.cmd == "replication":
        if a.action == "metrics":
            out = c.call("GET", "replication/metrics")
        else:
            out = c.call("PUT", f"replication/targets/{a.source_bucket}", {
                "endpoint": a.endpoint, "bucket": a.bucket, "access_key": a.access_key,
                "secret_key": a.secret_key, "region": a.region})
    elif a.cmd == "tier":
        if a.action == "list":
            out = c.call("GET", "tiers")
        else:
            out = c.call("PUT", f"tiers/{a.name}", {
                "type": "s3", "endpoint": a.endpoint, "bucket": a.bucket, "prefix": a.prefix,
                "access_key": a.access_key, "secret_key": a.secret_key, "region": a.region})
    elif a.cmd == "target":
        if a.action == "list":
            out = c.call("GET", "targets")
        else:
            body = {"role": a.role}
            for f in ("url", "brokers", "topic", "path", "auth_token"):
                if getattr(a, f):
                    body[f] = getattr(a, f)
            out = c.call("PUT", f"targets/{a.kind}/{a.name}", body)
    elif a.cmd == "kms":
        out = c.call("GET", "kms/status") if a.action == "status" else c.call("POST", f"kms/keys/{a.name}")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
