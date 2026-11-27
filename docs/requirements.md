# How Vulture meets the requirements

Status: **done** = in the code today, **partial** = works with caveats, **planned** = not built yet.

| Requirement | Status | How |
|---|---|---|
| Vultr Serverless Inference for reasoning | done (optional) | Stage 6 (`api/analyze.py`), OpenAI-compatible API at `https://api.vultrinference.com/v1`; needs `VULTR_INFERENCE_API_KEY` + `AGENT_MODEL`, otherwise rule-based only |
| Sandbox isolated from the app process | done | Fetch and detonation run in separate worker containers, never in the API; detonation on an internal network with a sinkhole ([architecture](architecture.md#what-is-isolated-and-how)) |
| Docker as sandbox boundary | done | `sandbox-images/`, containers created per scan by `api/orchestrator.py` (Docker/runc, no gVisor yet) |
| REST status + progress | done | `POST /api/scans`, `GET /api/scans/{id}?after=<event id>` (polled by the dashboard), cancel, evidence, re-analyze; no WebSocket yet (Part 3) |
| Dashboard: execution loop | done | `dashboard/index.html`: stage progress, event log, report |
| Vultr VM backend | planned | Runs on any Docker host; deploy notes in [infra/README.md](../infra/README.md), not deployed yet |
| Web app deployed on Vultr | planned | Same as above (dashboard is served by the API) |
| Throwaway Vultr instance per task | partial | `SANDBOX_MODE=vultr` (`api/vultr.py`): a VM per scan, destroyed afterwards, orphan janitor. Needs a Vultr key; mocked in tests, not yet run against the live API |
| Dashboard: retries, screenshot trail | partial | UI v2 shows retries and a screenshot filmstrip; screenshots come with the browser stage (Part 7). Runs on sample data with `?mock=1` |
| Approve-before-submit gates | planned | e.g. before running with real network, or before publishing a verdict |
| Vision models for screenshots | planned | Open URLs the package contacts in a headless browser and screenshot them |
| Playwright in Docker | planned | The browser step above |
| Resource limits: time and memory caps on every run | done | Per-container memory (no swap), CPU and PID caps, per-stage and whole-scan deadlines, concurrency cap. See [limits-and-lifecycle.md](limits-and-lifecycle.md) |
| Lifecycle discipline: reset or destroy the environment after each task | done | Labelled per-scan environment, verified teardown in `finally`, orphan reaper on startup and on a timer. See [limits-and-lifecycle.md](limits-and-lifecycle.md) |
| Access control | done (token optional) | Token auth, rate limits, upload and source validation. See [lock-down.md](lock-down.md) |
| Persistent scans | done | SQLite history, cancel, dedupe by pinned version, stored raw evidence for re-analysis |
| Agentic analysis | done (optional) | `api/investigator.py`: the model reads files, greps and re-runs the package while the sandbox is alive; steps are streamed as events |
