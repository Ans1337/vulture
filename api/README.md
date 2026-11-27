# API

- `app.py`: REST API (start scan, poll progress, get report) + serves the UI
- `orchestrator.py`: runs stages 1–5 in isolated containers
- `analyze.py`: stage 6, rule-based score + Vultr Inference agent
