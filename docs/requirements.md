# How Vulture meets the requirements

Status: **done** = in the code today, **partial** = works with caveats, **planned** = not built yet.

| Requirement | Status | How |
|---|---|---|
| Vultr Serverless Inference for reasoning | done (optional) | Stage 6 (`api/analyze.py`), OpenAI-compatible API at `https://api.vultrinference.com/v1`; needs `VULTR_INFERENCE_API_KEY` + `AGENT_MODEL`, otherwise rule-based only |
| Sandbox isolated from the app process | done | Fetch and detonation run in separate worker containers, never in the API; detonation on an internal network with a sinkhole ([architecture](architecture.md#what-is-isolated-and-how)) |
| Docker as sandbox boundary | done | `sandbox-images/`, containers created per scan by `api/orchestrator.py` (Docker/runc, no gVisor yet) |
| REST status + progress | done | `POST /api/scans`, `GET /api/scans/{id}` (polled by the dashboard); no WebSocket / streaming yet |
| Dashboard: execution loop | done | `dashboard/index.html`: stage progress, event log, report |
| Vultr VM backend | planned | Runs on any Docker host; deploy notes in [infra/README.md](../infra/README.md), not deployed yet |
| Web app deployed on Vultr | planned | Same as above (dashboard is served by the API) |
| Throwaway Vultr instance per task | planned | Today: throwaway Docker containers + network + volume per scan, removed afterwards |
| Dashboard: retries, screenshot trail | planned | |
| Approve-before-submit gates | planned | e.g. before running with real network, or before publishing a verdict |
| Vision models for screenshots | planned | Open URLs the package contacts in a headless browser and screenshot them |
| Playwright in Docker | planned | The browser step above |
