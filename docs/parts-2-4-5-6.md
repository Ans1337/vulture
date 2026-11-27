# Storage, UI v2, throwaway VMs and the AI investigator (Parts 2, 4, 5, 6)

## Part 2: storage and job control (`api/store.py`, `api/app.py`)
- Scans, events, reports and the raw sandbox evidence live in SQLite at `VULTURE_DB` (`/data/vulture.db`, in the `vulture-data` Docker volume). Redeploys keep history, and `/#/scan/<id>` is a permanent report URL.
- On startup, scans that a restart interrupted are marked `failed` ("interrupted by a server restart").
- `LIMIT_MAX_CONCURRENT` scans run and the rest wait as `queued`, up to `LIMIT_MAX_QUEUED`. After that `POST /api/scans` returns 429. Only the newest `LIMIT_HISTORY_MAX` finished scans are kept.
- `POST /api/scans/{id}/cancel` stops the containers (or VM) and tears everything down. The scan ends as `cancelled`.
- Dedupe: an exact `name@1.2.3` or `url#<40-hex commit>` that already has a finished scan returns `200 {id, deduped: true}`. Pass `force=true` to re-scan. Unpinned sources like `left-pad` are never deduped.
- `GET /api/scans/{id}/evidence` returns the raw evidence, and `POST /api/scans/{id}/reanalyze` re-runs stage 6 on it with the current rules and model, without detonating again.
- `GET /api/scans?q=&status=&verdict=&limit=` and `GET /api/scans/{id}?after=<event id>` (only new events) feed the UI.

## Part 4: UI v2 (`dashboard/`)
Hash routes in plain JS: `#/` landing (input, drag-and-drop, examples, how it works, recent scans), `#/scan/<id>` (live view that becomes the report), `#/history` (filters), `#/approvals`.

- **Live view:** stage timeline, a VM strip (created, booted, destroyed), persona × clock run cards with retry badges, the investigator's steps, a screenshot filmstrip, Cancel and Copy link.
- **Report:** verdict, the new `incomplete` state and coverage banner, confidence, "what it tried to do", the matrix heat-map, and tabs for honeytokens, network, processes, files, static findings and dormant code.
- **Sample data:** open `/?mock=1` to run the whole UI on `dashboard/mock.js` with no backend. Two sample scans play out live (a stealer and a benign package), and cancel and filters work. The mock matches the real API shapes, so dropping the flag uses the live API.
- Events that carry `data.run`, `data.vm`, `data.screenshot` or `data.approval` drive the run cards, VM strip, filmstrip and approval gates. The backend emits `vm` already. Per-run `run` events, screenshots (Part 7) and approvals (Part 8) don't exist yet, so those panels stay empty on live scans.

## Part 5: throwaway Vultr VM per scan (`api/vultr.py`)
`SANDBOX_MODE=vultr` runs the same orchestration code against the Docker daemon of a fresh Vultr instance (over SSH). The API container never executes the package.

1. Create the instance, tagged `vulture-scan` and `scan-<id>`, from a snapshot (`VULTR_SNAPSHOT_ID`, about a minute to boot) or from Ubuntu plus cloud-init that builds the images.
2. Wait until it is active and Docker is up. This honours cancel and `VULTR_BOOT_TIMEOUT`.
3. Run fetch, sandbox and detonate there, with the same limits and teardown as local mode.
4. **Delete the instance** in `finally`, retrying and verifying with the API that it's gone. A boot failure, timeout or cancel also deletes it.
5. A janitor deletes tagged instances that belong to no live scan: at startup, and every 5 minutes for ones older than `VULTR_VM_MAX_AGE`.

Setup: set `VULTR_API_KEY` and `VULTR_SSH_KEY_ID`, and mount the key's private half at `/run/secrets/vultr_ssh_key` (see `docker-compose.yml`). A firewall group (`VULTR_FIREWALL_GROUP_ID`) should allow inbound SSH from the app VM only. The VM's own host keys aren't pinned because the VM is brand new. The API container ships `openssh-client`.

**Not verified against the real Vultr API.** The client is tested against an in-memory fake. The plan, the OS id and the API field names need one real run. Costs are real, so keep `VULTR_VM_MAX_AGE` low.

## Part 6: AI investigator (`api/investigator.py`)
After the first detonation, while the sandbox is still alive, the model decides what to do next. It has four tools: `list_files`, `read_file`, `grep` (read-only, no network, in a throwaway container) and `rerun(persona, clock)` (one more detonation with the same isolation). The loop is bounded: `INVESTIGATOR_MAX_STEPS` (8), `INVESTIGATOR_MAX_RERUNS` (3), the scan deadline, and retries on model errors or bad JSON. Every step is an `investigate` event and shows live in the UI. The transcript is saved with the evidence and sent to the final verdict call.

- Package text is untrusted. The prompt says so, and the verdict rules from the audit still hold: rules are the floor and the AI can raise a verdict to SUSPICIOUS at most.
- The scan marker is masked as `<HONEYTOKEN>` in everything sent to the model, tool output included.
- Without `VULTR_INFERENCE_API_KEY` and `AGENT_MODEL` the step is skipped and the scan is rule-based, as before.

## Tests
`cd api && python3 -m unittest discover tests` (needs `fastapi` and `httpx`; no Docker). The suite covers storage, restart recovery, dedupe, cancel, the VM lifecycle against a fake Vultr API, the investigator loop with a scripted model, and marker masking.
