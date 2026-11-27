# Vulture

**Is this package safe to install?** Vulture takes a GitHub repo, a package name or uploaded files,
detonates it in an isolated sandbox on Vultr full of fake secrets and a fake internet, watches what it
does, and has an AI agent write a **Safe / Malware report**.

> Status: empty skeleton. The idea is being finalised; nothing is implemented yet.

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
api/              backend API: start scans, stream progress (REST + WebSocket)
dashboard/        web UI: scan timeline, findings, honeytoken hits, report
pipeline/         one folder per stage (1-fetch … 6-analyze)
sandbox-images/   container images used inside the sandbox (worker, sinkhole)
report/           report format (JSON schema)
infra/            Vultr VM provisioning, docker-compose, deploy scripts
samples/          test packages: benign + harmless fake malware
docs/             idea, architecture, requirements mapping
```

## Hackathon requirements

See [docs/requirements.md](docs/requirements.md).
