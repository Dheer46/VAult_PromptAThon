"""Chaos scenarios against the Docker Compose cluster (guide section 19.2).

Each scenario runs the correctness checker as background load, injects a fault,
restores it, waits for healing, and then verifies every acknowledged object.

  python tests/chaos/chaos.py list
  python tests/chaos/chaos.py kill-node          # 1
  python tests/chaos/chaos.py all --seconds 60
"""
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import correctness_checker as cc  # noqa: E402

COMPOSE = ["docker", "compose", "-f", os.path.join(os.path.dirname(__file__), "..", "..", "deploy",
                                                     "docker-compose.yml")]
ENDPOINT = os.environ.get("VAULT_ENDPOINT", "http://localhost:9000")


def sh(*args, check=False) -> str:
    r = subprocess.run(list(args), capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(r.stderr)
    return r.stdout.strip()


def dc(*args, check=False) -> str:
    return sh(*COMPOSE, *args, check=check)


def dexec(node: str, cmd: str) -> str:
    return dc("exec", "-T", node, "sh", "-c", cmd)


def ip(node: str) -> str:
    return dexec(node, "hostname -i").split()[0]


def cluster_ok() -> bool:
    import httpx
    try:
        return httpx.get(f"{ENDPOINT}/vault/health/cluster", timeout=3).status_code == 200
    except Exception:
        return False


def wait_healthy(timeout=180):
    t = time.time()
    while time.time() - t < timeout:
        if cluster_ok():
            return time.time() - t
        time.sleep(2)
    return None


def heal_all():
    for b in ("checker",):
        subprocess.run([sys.executable, "-m", "vault.admin.vaultctl", "--endpoint", ENDPOINT, "heal", b],
                       capture_output=True, cwd=os.path.join(os.path.dirname(__file__), "..", ".."))


# ------------------------------------------------------------------ faults
def kill_node():
    dc("kill", "node2")
    return lambda: dc("start", "node2")


def kill_two_nodes():
    dc("kill", "node2", "node3")
    return lambda: dc("start", "node2", "node3")


def wipe_drive():
    dexec("node2", "rm -rf /data/disk3/* /data/disk3/.vault.sys")
    return lambda: None


def bit_rot():
    script = ("for f in $(find /data -name 'part.*' | shuf -n 20); do "
              "sz=$(stat -c %s $f); off=$(shuf -i 40-$((sz>41?sz-1:41)) -n1); "
              "printf '\\xde\\xad' | dd of=$f bs=1 seek=$off conv=notrunc 2>/dev/null; done")
    for n in ("node1", "node3"):
        dexec(n, script)
    return lambda: None


def truncate_files():
    dexec("node4", "for f in $(find /data -name 'part.*' | shuf -n 10); do truncate -s 100 $f; done")
    return lambda: None


def partition():
    n4 = ip("node4")
    for n in ("node1", "node2", "node3"):
        dexec(n, f"iptables -A INPUT -s {n4} -j DROP && iptables -A OUTPUT -d {n4} -j DROP")

    def restore():
        for n in ("node1", "node2", "node3"):
            dexec(n, f"iptables -D INPUT -s {n4} -j DROP; iptables -D OUTPUT -d {n4} -j DROP")
    return restore


def slow_disk():
    dc("pause", "node3")  # a hung node looks like hung disks from the other nodes' view
    return lambda: dc("unpause", "node3")


def slow_network():
    dexec("node1", "tc qdisc add dev eth0 root netem delay 200ms loss 5%")
    return lambda: dexec("node1", "tc qdisc del dev eth0 root")


def kms_down():
    dc("stop", "kms")
    return lambda: (dc("start", "kms"), dc("up", "-d", "kms-init"))


def keystone_down():
    dc("stop", "keystone")
    return lambda: dc("start", "keystone")


def replication_target_down():
    dc("stop", "remote-s3")
    return lambda: dc("start", "remote-s3")


def concurrent_writers():
    import concurrent.futures
    c = cc.client(ENDPOINT)
    try:
        c.create_bucket(Bucket="race")
    except Exception:
        pass
    payloads = {i: os.urandom(50_000 + i) for i in range(50)}
    keys = [f"k{i}" for i in range(10)]

    def w(i):
        cl = cc.client(ENDPOINT)
        for k in keys:
            try:
                cl.put_object(Bucket="race", Key=k, Body=payloads[i])
            except Exception:
                pass
    with concurrent.futures.ThreadPoolExecutor(50) as ex:
        list(ex.map(w, range(50)))
    bad = [k for k in keys if c.get_object(Bucket="race", Key=k)["Body"].read() not in payloads.values()]
    print(json.dumps({"concurrent_writers_bad_keys": bad}))
    return lambda: None


SCENARIOS = {
    "kill-node": (kill_node, "No failed requests at LB, reads decode from parity, MRF + drive heal after return"),
    "kill-two-nodes": (kill_two_nodes, "Writes fail with 503 (below quorum); no corruption"),
    "wipe-drive": (wipe_drive, "Detected as unformatted -> drive heal to 100%"),
    "bit-rot": (bit_rot, "Reads still correct; vault_bitrot_detected_total rises; deep scan repairs"),
    "truncate": (truncate_files, "Detected by checksum -> healed"),
    "partition": (partition, "node4 can't take locks -> rejects writes; majority side continues"),
    "slow-disk": (slow_disk, "Paused node treated as offline after timeouts; requests don't hang"),
    "slow-network": (slow_network, "Higher latency, no errors, no data loss"),
    "kms-down": (kms_down, "Encrypted ops 503, plain ops fine; recovery automatic"),
    "keystone-down": (keystone_down, "Keystone users rejected (cached tokens until TTL), local users unaffected"),
    "replication-target-down": (replication_target_down, "Backlog grows, drains after restore"),
    "concurrent-writers": (concurrent_writers, "Every final object equals exactly one written version"),
}


def run_scenario(name: str, seconds: float) -> dict:
    fault, expected = SCENARIOS[name]
    print(f"== {name}: {expected}", flush=True)
    result: dict = {}
    load = threading.Thread(target=lambda: result.update(cc.run(ENDPOINT, seconds, 6)), daemon=True)
    load.start()
    time.sleep(min(10, seconds / 4))
    t_fault = time.time()
    restore = fault()
    time.sleep(seconds / 2)
    restore()
    t_restore = time.time()
    load.join()
    recovered = wait_healthy()
    heal_all()
    time.sleep(5)
    verify = cc.verify_all(ENDPOINT)
    out = {"scenario": name, "expected": expected, "load": result, "verify": verify,
           "fault_seconds": round(t_restore - t_fault, 1),
           "time_to_healthy_after_restore": recovered}
    print(json.dumps(out, indent=2), flush=True)
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("scenario", help="scenario name, 'all' or 'list'")
    p.add_argument("--seconds", type=float, default=60)
    a = p.parse_args()
    if a.scenario == "list":
        for k, (_, e) in SCENARIOS.items():
            print(f"{k:26s} {e}")
        return
    names = list(SCENARIOS) if a.scenario == "all" else [a.scenario]
    results = [run_scenario(n, a.seconds) for n in names]
    ok = all(r["verify"]["PASS"] for r in results)
    print(json.dumps({"scenarios": len(results), "all_acknowledged_objects_intact": ok}, indent=2))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    random.seed()
    main()
