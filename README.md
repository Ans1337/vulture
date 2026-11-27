# Vulture

**Is this package safe to install?** Vulture takes a GitHub repo, a package name or uploaded files,
detonates it in an isolated sandbox on Vultr full of fake secrets and a fake internet, watches what it
does, and has an AI agent write a **Safe / Malware report**.

> Status: **MVP**. Scans npm packages, GitHub repos and uploads in Docker sandboxes on your machine.
> Not yet: throwaway Vultr VM per scan, browser/screenshot step, approval gates, deploy to Vultr.

## Run it (needs Docker Desktop)

```bash
./start.sh            # builds the sandbox images, starts the app
open http://localhost:8000
```

`start.sh` creates `.env` from `.env.example` on first run. Add `VULTR_INFERENCE_API_KEY` and
`AGENT_MODEL` there to get the AI verdict; without them you get the rule-based verdict.
After editing `.env`: `docker compose up -d api`.

To see it catch something, upload `samples/fake-malware/fake-stealer.tgz` (created by `start.sh`).
It's **harmless fake malware**: it steals the planted fake secrets and sends them to a made-up host
that only exists inside the sandbox, and it has a time bomb that only fires 60+ days later outside CI.
Vulture catches both.

Stop it: `docker compose down`.

## Pipeline

| # | Stage | What happens |
|---|---|---|
| 1 | **Fetch** | Clone the repo or pull the package. Pin the exact version and hash so the report is reproducible. |
| 2 | **Static pass** | Unpack and scan: install scripts, obfuscation, encoded payloads, risky capabilities (env access, shell-outs, network calls). |
| 3 | **Build the sandbox** | Spin up an isolated VM, load a persona (generic or twin), plant honeytokens (fake keys, `.env`, wallets), wire the fake internet (sinkholed network that answers back). |
| 4 | **Detonate** | Install the package and run its entry points across the persona matrix, with the clock pushed forward so delayed payloads fire. |
| 5 | **Observe** | Log everything it touches: network requests, files read/written, credentials reached for, processes spawned, honeytoken hits. |
| 6 | **Analyze** | The agent reviews the traces plus the code paths that never executed, and reasons about what would trigger them. |

**Output:** a Safe / Malware report (`report/report.schema.json`).

## Repo layout

```
api/              backend API: start scans, poll progress, run the pipeline (orchestrator.py, analyze.py)
dashboard/        one-page web UI: stage progress + report
pipeline/         one folder per stage (1-fetch … 6-analyze)
sandbox-images/   worker (fetch, static scan, detonate) + sinkhole (fake internet)
report/           report format (JSON schema)
infra/            Vultr VM provisioning, docker-compose, deploy scripts
samples/          test packages: benign + harmless fake malware
docs/             idea, architecture, requirements mapping
```

## Hackathon requirements

See [docs/requirements.md](docs/requirements.md).
