# What the dashboard reads from the API

The dashboard talks to the backend only through `dashboard/js/api.js`, and turns scans into screens in
`dashboard/js/model.js`. This page lists what it uses, so backend changes can be checked against it.
Open the dashboard with `?mock=1` to see every item below drawn from sample data.

## Calls

| Call | Used for |
|---|---|
| `GET /api/limits` | Deciding at load whether a Vulture API is there. No API means sample data |
| `POST /api/nonce` | Minting the personal key on first use (kept in `localStorage.vultureNonce`) |
| `GET /api/scans?limit=` | Recent scans on the landing page, the history list |
| `GET /api/scans/{id}?after=` | The live scan view (polled every 1.2 s with the last event id) and the report |
| `POST /api/scans` (`source`, `file`, `force`) | Starting a scan. `{deduped: true}` opens the stored report, Re-scan sends `force=true` |
| `POST /api/scans/{id}/cancel` | The Cancel button |
| `GET /api/scans?status=running` | Finding pending approvals, see below |
| `POST /api/approvals/{id}/approve` and `/reject` | The approval buttons. **Not in the API yet** |

Every call sends `Authorization: Bearer <APP_TOKEN>` when the browser has one (`localStorage.vultureToken`,
asked for on a 401 that is not about the nonce) and `X-Vulture-Nonce`. The storage keys are the same ones
the classic dashboard uses, so both show the same scans.

## Events

The scan view is driven by `events[].data`. Shapes the backend sends today:

| `data` | Sent by | Drawn as |
|---|---|---|
| `personas`, `clocks` | orchestrator, when the sinkhole is up | the empty persona × clock grid |
| `run` (+ `honeytoken_hits` on the last event of a run) | worker | run cells filling in |
| `vm`: `creating`, `created`, `ready`, `destroyed`, `destroy_failed` (+ `vm_report`) | `vultr.py` | the VM strip |
| `tool`, `args`, `thought` on stage `investigate` | `investigator.py` | investigator steps |
| `stop_reason`, `conclusion` on stage `investigate` | `investigator.py` | the closing investigator step |
| `retry` | `investigator.py` | "retried N×" on the stage |
| `limits` | orchestrator, before the fetch | not drawn; it and the `vm` events do not move the timeline past `sandbox` |
| `lifecycle` | orchestrator teardown | "Sandbox: destroyed after the scan" in the report |

Shapes the dashboard already draws but nothing sends yet:

| `data` | Meant for | Drawn as |
|---|---|---|
| `run` + `state: "running" \| "done"`, `network`, `processes`, `retry`, `retry_reason` | per-run progress | live numbers and a retry mark on a run cell |
| `result` next to `tool` | investigator | one line under the step saying what the tool found |
| `screenshot` (image URL), `url`, `vision` | Part 7 | the screenshot trail, with the vision model's caption |
| `approval`: `{id, title, detail, kind, state}` with state `pending`, `approved` or `rejected` | Part 8 | the approval gate on the scan, the Approvals page and the nav count |

`kind` is `live_internet`, `publish_verdict` or `spend`, and only picks the icon.

## Approvals

There is no approvals endpoint, so the dashboard finds pending approvals by reading the events of running
scans, and only when you navigate, to stay inside the rate limit. An endpoint that lists pending and past
approvals (who decided, when) would let the Approvals page show its audit log on live data. The sample
data has one.

## Report

The report page reads the object `api/analyze.py:report()` returns: `verdict`, `verdict_source`,
`rules.{risk_score, reasons, coverage, unresolved}`, `ai.{verdict, confidence, summary, recommendation,
indicators, dormant_triggers, note, error}`, `isolation`, and from `evidence`: `target`, `matrix`,
`honeytoken_access`, `exfiltration`, `dns_lookups`, `requests`, `processes`,
`files_written_outside_project`, `install_scripts`, `static_findings`, `dormant_code`.
