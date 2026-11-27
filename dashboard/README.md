# Dashboard (UI v2)

Design direction, tokens and the hero image prompt: [docs/design.md](../docs/design.md).

Plain HTML, CSS and ES modules. No build step: the API container copies this folder as is.

```
index.html          shell: nav, <main id="app">, footer, the ink filter for the verdict stamp
css/app.css         design tokens + every component (one paper theme)
fonts/              Fraunces, Instrument Sans, IBM Plex Mono (self-hosted, OFL)
img/hero.webp       the engraving in the landing hero
js/main.js          hash router, sample-data switch, approvals count, access-token and personal-key sheets
js/api.js           the only module that talks to the backend
js/mock.js          sample backend that replays scripted scans in the browser
js/model.js         turns raw events + report into what the views draw
js/ui.js            helpers and the icon set
js/views/           landing, scan (live), report, history, approvals

classic.html        the previous dashboard, kept as "Classic view" (uses app.js, mock.js, style.css)
```

Routes: `#/` · `#/scan/{id}` · `#/report/{id}` · `#/history` · `#/approvals`

## Run it

- With the API: `./start.sh`, then open http://localhost:8000.
- Without Docker (sample data): `python3 -m http.server 5173 -d dashboard`, then open http://localhost:5173.
  With no API answering, the dashboard switches to sample data by itself.
- `?mock=1` forces sample data on any host, `?mock=0` forces the live API.

Sample packages: `fake-stealer@1.0.0` (malware), `chrono-helpers@2.4.1` (time bomb),
`release-notes-gen@0.3.1` (pauses on an approval gate), `left-pad` (safe), `@types/node` (inconclusive).

What the dashboard reads from the API, and the event shapes it draws: [docs/ui-contract.md](../docs/ui-contract.md).
