# How Vulture meets the requirements

| Requirement | Plan |
|---|---|
| Vultr VM backend | `api/` runs on a Vultr Cloud Compute VM |
| Web app deployed on Vultr | `dashboard/`, served from the same VM |
| Vultr Serverless Inference for reasoning | Stage 6 (Analyze), OpenAI-compatible API at `https://api.vultrinference.com/v1` |
| Sandbox isolated from the app process | Stages 3–5 run in a throwaway Vultr instance or Docker container, never in the API |
| Docker as sandbox boundary | `sandbox-images/` |
| REST / WebSocket status + streaming | `api/` |
| Dashboard: execution loop, retries, screenshot trail | `dashboard/` |
| Approve-before-submit gates | e.g. before running with real network, or before publishing / reporting a verdict |
| Throwaway Vultr instance per task | one instance per scan, destroyed afterwards |
| Vision models for screenshots | open URLs the package contacts in a headless browser and screenshot them |
| Playwright in Docker | the browser step above |
