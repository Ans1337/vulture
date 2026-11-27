# Resource limits and lifecycle discipline

## Resource limits: time and memory caps on every run

Defined in [`api/limits.py`](../api/limits.py), tunable through `.env` (`LIMIT_*`), and visible at `GET /api/limits`.

| Container | Memory (swap off) | CPU | PIDs | Time cap |
|---|---|---|---|---|
| fetch + static pass | 1g | 1 | 512 | 300s |
| sinkhole (fake internet) | 256m | 0.5 | 512 | dies with the scan |
| detonate (persona x clock matrix) | 1g, plus 1g tmpfs | 2 | 512 | 900s total, 60s per command |
| **whole scan** | | | | **1500s hard deadline** |
| api / docker-proxy (compose) | 512m / 64m | | 256 / 64 | |

- Swap is disabled (`memswap_limit == mem_limit`), so the memory cap is real.
- Each stage's timeout is `min(stage cap, time left in the scan)`, so stages cannot add up past `LIMIT_SCAN_TIMEOUT`.
- A watchdog kills any container that outlives its cap.
- A time or memory kill (`OOMKilled`) is reported in the scan log and as `limit_hit` in the detonate result. A package that exhausts its sandbox is itself a finding.
- Fleet caps: `LIMIT_MAX_CONCURRENT` scans run at once, up to `LIMIT_MAX_QUEUED` wait, and more get HTTP 429. Finished scans in memory are capped by `LIMIT_HISTORY_MAX`.

## Lifecycle: destroy the environment after each task

One scan means one environment: a labelled volume, an internal network, a sinkhole and a worker container per stage. All of them carry the label `vulture.scan=<id>`.

1. **Teardown after every scan.** `lifecycle.teardown()` runs in `run_scan`'s `finally`, so it happens on success, failure, timeout and cancellation. It finds everything by label rather than from a list in memory, and removes containers, then the network, then the volume. It retries, then re-queries Docker to prove nothing is left.
2. **The proof is surfaced.** The `destroy` stage appears in the timeline. Its event, and `scan.lifecycle` in the API, say what was removed or what survived (`destroyed: true/false`, `leftover: [...]`).
3. **Reaper for crashes.** If the API dies mid-scan, nothing runs `finally`. `lifecycle.start_reaper()` destroys every labelled resource at startup, because nothing can be live after a restart. It then runs every 5 minutes and removes anything older than `LIMIT_ORPHAN_MAX_AGE` that belongs to no live scan.
4. **Nothing is reused.** Containers are never restarted or shared between scans, volumes are per scan, and the honeytoken marker is fresh each time.

## Tests

```bash
cd api && python3 -m unittest discover tests
```

These use fakes, so Docker isn't needed. They cover limit validation, full teardown with a retry, reporting of leftovers, and the reaper sparing live scans.

## Not yet done

The later "throwaway Vultr VM per scan" step (`VULTR_API_KEY`) isn't implemented. When it is, the same two rules apply to the VM: set a TTL and destroy it in `finally`.
