"""Resource limits for every sandbox run. One place, env-configurable, validated at import.

Every container Vulture starts gets a memory cap (swap disabled), a CPU cap, a PID cap and a
wall-clock deadline. A scan as a whole also has a hard deadline (SCAN_TIMEOUT).
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int, lo: int = 1) -> int:
    raw = os.environ.get(name, "")
    try:
        v = int(raw) if raw.strip() else default
    except ValueError:
        raise SystemExit(f"{name} must be an integer, got {raw!r}")
    if v < lo:
        raise SystemExit(f"{name} must be >= {lo}, got {v}")
    return v


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name, "")
    try:
        v = float(raw) if raw.strip() else default
    except ValueError:
        raise SystemExit(f"{name} must be a number, got {raw!r}")
    if v <= 0:
        raise SystemExit(f"{name} must be > 0, got {v}")
    return v


def _mem(name: str, default: str) -> str:
    """Docker-style size like 512m / 1g. Returned as-is after a sanity check."""
    v = os.environ.get(name, "").strip().lower() or default
    if not (v[:-1].isdigit() and v[-1] in "kmg"):
        raise SystemExit(f"{name} must look like 512m or 1g, got {v!r}")
    return v


@dataclass(frozen=True)
class Limits:
    # --- memory (swap is always disabled: memswap_limit == mem_limit) ---
    fetch_mem: str
    detonate_mem: str
    sinkhole_mem: str
    tmpfs_size: str          # writable scratch space inside the read-only detonation container
    # --- cpu / processes ---
    fetch_cpus: float
    detonate_cpus: float
    sinkhole_cpus: float
    pids: int
    # --- time (seconds) ---
    fetch_timeout: int       # fetch + static pass
    detonate_timeout: int    # whole persona x clock matrix
    step_timeout: int        # one command inside the matrix (passed to the worker)
    scan_timeout: int        # hard cap for the entire scan, all stages
    # --- fleet ---
    max_concurrent: int      # scans running at once
    max_queued: int          # scans waiting for a slot before the API says 429
    history_max: int         # finished scans kept in memory
    orphan_max_age: int      # reaper: seconds before an unclaimed sandbox resource is destroyed

    @staticmethod
    def nano(cpus: float) -> int:
        return int(cpus * 1_000_000_000)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def load() -> Limits:
    return Limits(
        fetch_mem=_mem("LIMIT_FETCH_MEM", "1g"),
        detonate_mem=_mem("LIMIT_DETONATE_MEM", "1g"),
        sinkhole_mem=_mem("LIMIT_SINKHOLE_MEM", "256m"),
        tmpfs_size=_mem("LIMIT_TMPFS_SIZE", "1g"),
        fetch_cpus=_float("LIMIT_FETCH_CPUS", 1.0),
        detonate_cpus=_float("LIMIT_DETONATE_CPUS", 2.0),
        sinkhole_cpus=_float("LIMIT_SINKHOLE_CPUS", 0.5),
        pids=_int("LIMIT_PIDS", 512),
        fetch_timeout=_int("LIMIT_FETCH_TIMEOUT", 300),
        detonate_timeout=_int("LIMIT_DETONATE_TIMEOUT", 900),
        step_timeout=_int("SCAN_STEP_TIMEOUT", 60),
        scan_timeout=_int("LIMIT_SCAN_TIMEOUT", 1500),
        max_concurrent=_int("LIMIT_MAX_CONCURRENT", 2),
        max_queued=_int("LIMIT_MAX_QUEUED", 8, lo=0),
        history_max=_int("LIMIT_HISTORY_MAX", 200),
        orphan_max_age=_int("LIMIT_ORPHAN_MAX_AGE", 3600),
    )


LIMITS = load()
