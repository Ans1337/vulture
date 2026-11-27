# Architecture

```
browser ──HTTP──> api (FastAPI, 127.0.0.1:8000) ──> docker-proxy (filtered Docker API) ──> Docker
                   │                                         │ per scan:
                   │                                         ├─ fetch container     (normal network)
                   │                                         ├─ internal network    (no route out)
                   │                                         ├─ sinkhole container  (fake internet)
                   │                                         └─ detonate container  (sinkhole only)
                   └──HTTPS──> Vultr Serverless Inference (optional, evidence in, JSON verdict out)
```

- **api** (`api/app.py`, `api/orchestrator.py`, `api/analyze.py`): serves the dashboard, accepts a
  scan (npm name, GitHub URL or upload, read into memory, 50 MB max), runs it in a background thread,
  keeps scans **in memory**. It never executes the package itself. Container: non-root user,
  read-only rootfs, `/tmp` tmpfs, all capabilities dropped, no-new-privileges.
- **docker-proxy** (`tecnativa/docker-socket-proxy`): the only path from the API to Docker. Allows
  `CONTAINERS`, `NETWORKS`, `VOLUMES` and `POST`; denies images, exec, build and the rest. Not
  published on any host port.
- **worker image** (`sandbox-images/worker`): Ubuntu + Node 20 + strace + libfaketime; runs
  `fetch.py` (stages 1-2) and `detonate.py` (stages 4-5).
- **sinkhole image** (`sandbox-images/sinkhole`): answers every DNS query with its own IP and every
  HTTP / TLS / raw TCP connection on common ports, logging each as JSON.

## One scan

1. **Fetch + static** (fetch container): `npm pack`, `git clone` or the upload; pin version and
   sha256; `npm install --ignore-scripts --omit=dev`; static scan of the source. Results go to a
   per-scan Docker volume.
2. **Sandbox**: create an `internal` bridge network for this scan and start the sinkhole on it.
3. **Detonate** (detonate container): plant honeytokens (AWS, npm, SSH, git, wallets, Docker,
   kube, `.env`), each containing a per-scan random marker. For every persona x clock pair, run the
   package's install lifecycle scripts and load its entry points under `strace -f`.
   - personas: `developer` (plain shell env) and `ci` (GitHub Actions env vars, fake tokens); `server`
     is available via `SCAN_PERSONAS`.
   - clocks: `0` and `+90d` via libfaketime (`SCAN_CLOCKS`), so time bombs fire.
4. **Observe**: parse strace (processes, files read/written outside the project, honeytoken access,
   connections) and the sinkhole log (DNS, HTTP, TLS SNI, TCP payloads). The marker showing up in
   sinkhole traffic is proof of exfiltration.
5. **Analyze** (in the API process): rule-based score. If `VULTR_INFERENCE_API_KEY` and `AGENT_MODEL`
   are set, the evidence (truncated JSON) goes to the model on Vultr Serverless Inference, which also
   reasons about suspicious code that never ran and what would trigger it, and returns the verdict.
6. **Cleanup**: all scan containers, the network and the volume are force-removed, also on failure.

Verdicts: **safe** (no threats found within the scope of this check), **suspicious**, **malware**,
**incomplete** (nothing executed or detonation failed; no basis for a verdict).

## What is isolated and how

Isolation technology is **Docker / runc** (Linux namespaces + cgroups, shared host kernel). There is no
gVisor or microVM layer yet.

| Component | Network | Hardening |
|---|---|---|
| fetch container | normal Docker network (needs the registry / GitHub) | `cap_drop ALL`, no-new-privileges, mem 1g, pids 512. Only downloads: `npm install --ignore-scripts`, nothing from the package is executed. |
| detonate container | per-scan `internal` Docker network, no route out; DNS points to the sinkhole | `cap_drop ALL`, no-new-privileges, read-only rootfs, tmpfs `/tmp`, mem 1g, 2 CPUs, pids 512, non-root uid 1000, scan volume mounted **read-only**, no Docker socket. |
| sinkhole | same internal network only | Being hardened in parallel (non-root, `cap_drop ALL`, read-only, resource limits). |
| api | default compose network; port on `127.0.0.1` by default | non-root, read-only rootfs, `cap_drop ALL`, no-new-privileges. Talks to Docker only via docker-proxy. |

- **Honeytokens**: a fresh random marker per scan, so a hit is unambiguous and cannot come from an
  earlier scan.
- **Persona x clock matrix**: CI environment variables and libfaketime (+90 days) to trigger code that
  only acts in CI or after a date.
- **Observation**: strace inside the detonate container plus the sinkhole's logs. The package cannot
  reach anything real: its "internet" is the sinkhole.
- **LLM**: called only from the backend, with evidence as text. It gets **no tools** and cannot touch
  the sandbox or the host. Its output is parsed as JSON and only chooses among the known verdicts.
- **Lifetime**: everything created for a scan is removed when it ends.

## Known limitations

- **Fetch container has internet access**, including the cloud metadata endpoint `169.254.169.254`
  when running on a cloud VM. Nothing from the package runs there, but npm / git do. On a VM, drop that
  traffic with an iptables rule in the `DOCKER-USER` chain (see [infra/README.md](../infra/README.md)).
- **docker-proxy allows POST + CONTAINERS**: whoever controls the API can create any container,
  including a privileged one with host mounts, which is host-root equivalent. The proxy filters URLs,
  not request bodies; a body-filtering authorization proxy is future work.
- **No authentication on the API.** Bound to `127.0.0.1` by default; on a VM use a reverse proxy with
  auth or set `VULTURE_BIND` knowingly.
- **No retry when the sandbox dies.** If the detonate container crashes or is killed mid-scan, the
  scan is not re-run in a fresh sandbox: the report is built from whatever was captured so far, with
  "detonation failed: …" in the reasons (`incomplete` if nothing ran). A bounded retry is future work.
- **Scans live in memory**: lost on restart; no persistence.
- **No deduplication**: concurrent scans of the same package run separately; no concurrency limit.
- **Shared kernel**: Docker/runc only; a kernel exploit from the detonate container would reach the
  host. gVisor or a throwaway Vultr VM per scan is planned.
- **Not yet deployed to Vultr**; runs locally / on any Docker host.
- **npm only**: PyPI and other ecosystems are not supported yet.
- Evasion: malware that detects the sandbox, needs real network replies or waits longer than the
  clock shift can stay dormant. The LLM's dormant-code review is a mitigation, not a guarantee.
