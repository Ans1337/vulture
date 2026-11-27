"""Lifecycle discipline: every scan's environment is destroyed afterwards, and verified gone.

- teardown(scan_id): removes the scan's containers, network and volume (found by label/name, so it
  works even if the orchestrator lost track of something), then re-checks that nothing is left.
- reap(): safety net for crashes. Destroys sandbox resources that belong to no live scan.
  Runs once at API startup (nothing can be live yet) and then periodically (age-based).

Everything the orchestrator creates carries the label  vulture.scan=<scan id>.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Iterable

import docker

log = logging.getLogger("vulture.lifecycle")
LABEL = "vulture.scan"


def _age(created: str) -> float:
    """Seconds since a Docker timestamp like 2026-11-27T10:58:00.123456789Z (0 if unparseable)."""
    try:
        t = datetime.strptime(created[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - t).total_seconds())
    except Exception:
        return 0.0


def _find(client, scan_id: str | None):
    """All sandbox resources, for one scan or (scan_id=None) for every scan."""
    flt = {"label": f"{LABEL}={scan_id}" if scan_id else LABEL}
    return (client.containers.list(all=True, filters=flt),
            client.networks.list(filters=flt),
            client.volumes.list(filters=flt))


def _destroy(containers, networks, volumes) -> dict:
    counts = {"containers": 0, "networks": 0, "volumes": 0, "errors": []}
    for c in containers:                      # containers first: networks/volumes can't go while in use
        try:
            c.remove(force=True, v=True)
            counts["containers"] += 1
        except docker.errors.NotFound:
            pass
        except Exception as e:
            counts["errors"].append(f"container {c.name}: {e}")
    for n in networks:
        try:
            n.remove()
            counts["networks"] += 1
        except docker.errors.NotFound:
            pass
        except Exception as e:
            counts["errors"].append(f"network {n.name}: {e}")
    for v in volumes:
        try:
            v.remove(force=True)
            counts["volumes"] += 1
        except docker.errors.NotFound:
            pass
        except Exception as e:
            counts["errors"].append(f"volume {v.name}: {e}")
    return counts


def teardown(client, scan_id: str, retries: int = 3) -> dict:
    """Destroy one scan's environment and prove it. Returns what was removed and what (if anything) survived."""
    counts: dict = {"containers": 0, "networks": 0, "volumes": 0, "errors": []}
    leftover: list[str] = []
    for attempt in range(retries):
        c, n, v = _find(client, scan_id)
        if not (c or n or v):
            leftover = []
            break
        got = _destroy(c, n, v)
        for k in ("containers", "networks", "volumes"):
            counts[k] += got[k]
        counts["errors"] = got["errors"]
        time.sleep(0.5 * (attempt + 1))
        c, n, v = _find(client, scan_id)
        leftover = [x.name for x in (*c, *n, *v)]
        if not leftover:
            break
    counts["destroyed"] = not leftover
    counts["leftover"] = leftover
    if leftover:
        log.error("scan %s: environment NOT fully destroyed: %s", scan_id, leftover)
    return counts


def reap(client, live: Iterable[str] = (), max_age: int = 0) -> dict:
    """Destroy sandbox resources that belong to no live scan and are older than max_age seconds."""
    live = set(live)
    c, n, v = _find(client, None)

    def orphan(res, created):
        sid = (res.attrs.get("Labels") or res.attrs.get("Config", {}).get("Labels") or {}).get(LABEL)
        return sid not in live and _age(created) >= max_age

    c = [x for x in c if orphan(x, x.attrs.get("Created", ""))]
    n = [x for x in n if orphan(x, x.attrs.get("Created", ""))]
    v = [x for x in v if orphan(x, x.attrs.get("CreatedAt", ""))]
    got = _destroy(c, n, v)
    if any(got[k] for k in ("containers", "networks", "volumes")):
        log.warning("reaper destroyed orphans: %s", got)
    return got


def start_reaper(get_live, max_age: int, interval: int = 300) -> threading.Event:
    """Reap once now (everything is an orphan after a restart), then every `interval` seconds."""
    stop = threading.Event()

    def loop():
        first = True
        while not stop.is_set():
            try:
                reap(docker.from_env(), live=get_live(), max_age=0 if first else max_age)
            except Exception:
                log.exception("reaper pass failed")
            first = False
            stop.wait(interval)

    threading.Thread(target=loop, daemon=True, name="vulture-reaper").start()
    return stop
