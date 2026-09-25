"""The correctness checker — the most important test.

1. Writes objects with random sizes and records (key, sha256, size) in a local SQLite
   file ONLY after the PUT returned 200.
2. Continuously reads random recorded keys and verifies the SHA-256.
3. `verify-all` reads every recorded key.

Pass criterion: zero mismatches and zero missing acknowledged objects, ever. A write
that returned an error may or may not exist — that's allowed. An acknowledged write
that's lost or wrong is a bug.

  python tests/chaos/correctness_checker.py run --seconds 120 --workers 8
  python tests/chaos/correctness_checker.py verify-all
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sqlite3
import threading
import time

import boto3
from botocore.config import Config

DB = os.environ.get("CHECKER_DB", "checker.sqlite")
BUCKET = os.environ.get("CHECKER_BUCKET", "checker")
SIZES = [0, 1, 1000, 100_000, 1 << 20, 3 * (1 << 20) + 17, 9 * (1 << 20)]


def client(endpoint: str):
    return boto3.client("s3", endpoint_url=endpoint,
                        aws_access_key_id=os.environ.get("VAULT_ACCESS_KEY", "vaultadmin"),
                        aws_secret_access_key=os.environ.get("VAULT_SECRET_KEY", "vaultadmin-secret"),
                        region_name="us-east-1",
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 3},
                                      connect_timeout=5, read_timeout=60,
                                      request_checksum_calculation="when_required",
                                      response_checksum_validation="when_required"))


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.c = {"put_ok": 0, "put_err": 0, "get_ok": 0, "get_err": 0, "mismatch": 0, "missing": 0}
        self.lat = {"put": [], "get": []}

    def inc(self, k, lat=None, op=None):
        with self.lock:
            self.c[k] += 1
            if lat is not None:
                self.lat[op].append(lat)

    def report(self) -> dict:
        def pct(xs, p):
            xs = sorted(xs)
            return round(xs[min(len(xs) - 1, int(len(xs) * p))] * 1000, 1) if xs else 0
        c = self.c
        total = c["put_ok"] + c["put_err"] + c["get_ok"] + c["get_err"]
        return {**c, "availability_pct": round(100 * (c["put_ok"] + c["get_ok"]) / total, 2) if total else 100,
                "put_p50_ms": pct(self.lat["put"], .5), "put_p99_ms": pct(self.lat["put"], .99),
                "get_p50_ms": pct(self.lat["get"], .5), "get_p99_ms": pct(self.lat["get"], .99)}


def db():
    con = sqlite3.connect(DB, check_same_thread=False, isolation_level=None)
    con.execute("create table if not exists acked (key text primary key, sha text, size int, t real)")
    return con


def run(endpoint: str, seconds: float, workers: int, read_ratio: float = 0.6) -> dict:
    s3 = client(endpoint)
    try:
        s3.create_bucket(Bucket=BUCKET)
    except Exception:
        pass
    con = db()
    dblock = threading.Lock()
    stats = Stats()
    stop = time.time() + seconds

    def worker(wid):
        rnd = random.Random(wid * 7919 + int(time.time()))
        c = client(endpoint)
        while time.time() < stop:
            with dblock:
                keys = con.execute("select key, sha from acked order by random() limit 1").fetchall()
            if keys and rnd.random() < read_ratio:
                key, sha = keys[0]
                t = time.time()
                try:
                    body = c.get_object(Bucket=BUCKET, Key=key)["Body"].read()
                    stats.inc("get_ok", time.time() - t, "get")
                    if hashlib.sha256(body).hexdigest() != sha:
                        stats.inc("mismatch")
                        print(f"MISMATCH {key}", flush=True)
                except c.exceptions.NoSuchKey:
                    stats.inc("missing")
                    print(f"MISSING {key}", flush=True)
                except Exception:
                    stats.inc("get_err")
            else:
                size = rnd.choice(SIZES)
                data = os.urandom(size)
                key = f"w{wid}/{time.time_ns()}"
                t = time.time()
                try:
                    c.put_object(Bucket=BUCKET, Key=key, Body=data)
                except Exception:
                    stats.inc("put_err")
                    continue
                stats.inc("put_ok", time.time() - t, "put")
                with dblock:  # record only after the 200
                    con.execute("insert into acked values (?,?,?,?)",
                                (key, hashlib.sha256(data).hexdigest(), size, time.time()))
    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return stats.report()


def verify_all(endpoint: str) -> dict:
    c = client(endpoint)
    con = db()
    rows = con.execute("select key, sha from acked").fetchall()
    lost, wrong, errs = [], [], []
    for key, sha in rows:
        for attempt in range(3):
            try:
                body = c.get_object(Bucket=BUCKET, Key=key)["Body"].read()
                if hashlib.sha256(body).hexdigest() != sha:
                    wrong.append(key)
                break
            except c.exceptions.NoSuchKey:
                lost.append(key)
                break
            except Exception as e:
                if attempt == 2:
                    errs.append((key, str(e)[:100]))
                time.sleep(1)
    return {"acknowledged": len(rows), "lost": len(lost), "wrong": len(wrong), "unreadable": len(errs),
            "lost_keys": lost[:10], "wrong_keys": wrong[:10], "PASS": not lost and not wrong and not errs}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("mode", choices=["run", "verify-all"])
    p.add_argument("--endpoint", default=os.environ.get("VAULT_ENDPOINT", "http://localhost:9000"))
    p.add_argument("--seconds", type=float, default=60)
    p.add_argument("--workers", type=int, default=8)
    a = p.parse_args()
    out = run(a.endpoint, a.seconds, a.workers) if a.mode == "run" else verify_all(a.endpoint)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
