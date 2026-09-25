"""format.json: the cluster layout, written once to every drive on first start.

The node with the lowest name formats a blank cluster once it can reach every
peer; the others wait until they read a quorum of consistent format.json files.
After the first format, nodes start even if some peers are down (quorum rules).
"""
from __future__ import annotations

import asyncio
import json
import uuid
from collections import Counter

from .. import errors
from ..observability.log import log
from .storage_api import SYS_VOL, StorageAPI

FORMAT_FILE = "format.json"


def choose_set_size(total: int, requested: int = 0) -> int:
    if requested:
        if total % requested:
            raise ValueError(f"{total} drives can't be split into sets of {requested}")
        return requested
    for size in range(16, 1, -1):  # largest set size <= 16 that divides the drive count
        if total % size == 0:
            return size
    return total


def new_format(n_drives: int, set_size: int, parity: int) -> dict:
    ids = [str(uuid.uuid4()) for _ in range(n_drives)]
    return {"version": 1, "deployment_id": str(uuid.uuid4()),
            "sets": [ids[i:i + set_size] for i in range(0, n_drives, set_size)],
            "set_size": set_size, "parity": parity, "distribution_algo": "crc32-v1"}


def _layout_key(fmt: dict) -> str:
    return json.dumps({"d": fmt["deployment_id"], "s": fmt["sets"]}, sort_keys=True)


async def read_formats(drives: list[StorageAPI]) -> list[dict | Exception]:
    async def one(d):
        return json.loads(await d.read_all(SYS_VOL, FORMAT_FILE))
    return list(await asyncio.gather(*[one(d) for d in drives], return_exceptions=True))


async def write_format(d: StorageAPI, layout: dict, slot: int) -> None:
    flat = [u for s in layout["sets"] for u in s]
    fmt = {**layout, "this": flat[slot]}
    await d.write_all(SYS_VOL, FORMAT_FILE, json.dumps(fmt, indent=1).encode())
    d.drive_id = flat[slot]


async def load_or_format(drives: list[StorageAPI], set_size: int, parity: int,
                         i_am_formatter: bool, wait: bool = True) -> tuple[dict, list[int]]:
    """Returns (layout, slots_needing_heal)."""
    n = len(drives)
    attempt = 0
    while True:
        fmts = await read_formats(drives)
        good = [f for f in fmts if isinstance(f, dict)]
        blank = [i for i, f in enumerate(fmts) if isinstance(f, (errors.FileNotFound, errors.VolumeNotFound))]
        reachable = [i for i, f in enumerate(fmts) if not isinstance(f, Exception)
                     or isinstance(f, (errors.FileNotFound, errors.VolumeNotFound))]
        if good:
            key, count = Counter(_layout_key(f) for f in good).most_common(1)[0]
            if count > n // 2 or (count == len(good) and not wait):
                layout = next(f for f in good if _layout_key(f) == key)
                flat = [u for s in layout["sets"] for u in s]
                heal = []
                for i, f in enumerate(fmts):
                    if isinstance(f, dict) and _layout_key(f) == key:
                        drives[i].drive_id = f.get("this", flat[i])
                    elif i in blank:
                        # a blank drive in a slot the layout expects: replaced drive
                        await write_format(drives[i], layout, i)
                        heal.append(i)
                        log.info("replaced drive formatted", endpoint=drives[i].endpoint, slot=i)
                    else:
                        drives[i].drive_id = flat[i]
                return layout, heal
        if not good and len(blank) == n and i_am_formatter:
            layout = new_format(n, set_size, parity)
            res = await asyncio.gather(*[write_format(d, layout, i) for i, d in enumerate(drives)],
                                       return_exceptions=True)
            failed = [r for r in res if isinstance(r, BaseException)]
            if not failed:
                log.info("cluster formatted", deployment_id=layout["deployment_id"],
                         sets=len(layout["sets"]), set_size=set_size,
                         ec=f"{set_size - parity}+{parity}")
                return layout, []
        attempt += 1
        if attempt % 10 == 1:
            log.info("waiting for cluster format", reachable=len(reachable), total=n,
                     formatted=len(good))
        await asyncio.sleep(1.0)
