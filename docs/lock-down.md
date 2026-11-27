# Part 1: lock-down

The public site can't be used to run arbitrary code on our VM or to burn AI credits.
The code is in [`api/security.py`](../api/security.py).

| Protection | How |
|---|---|
| **Access token** | `APP_TOKEN` is optional. When it is set (minimum 16 characters), every `/api/*` call needs `Authorization: Bearer <token>` or `X-Vulture-Token`. The check is constant-time. The dashboard HTML stays public. When it is empty the API is open and logs a warning at startup. It asks for the token once, stores it in the browser and asks again on a 401. |
| **Personal nonce** | Every scan belongs to the person who created it. Each user has their own secret nonce (`X-Vulture-Nonce`, 32-128 chars of `A-Za-z0-9_-`), minted with `POST /api/nonce` (256 random bits, nothing stored). Listing, reading, evidence, cancel and re-analyze all require it, and only the scan's owner gets through. Someone else's scan answers `404`, exactly like a scan that doesn't exist. Only the SHA-256 of the nonce is stored, so a database leak can't be used to impersonate anyone. Re-scan dedupe is per owner, so it can't hand you another user's report. The dashboard mints one on first use, keeps it in `localStorage` and shows it under **Your key** (paste it on another device to see the same scans). Scans from before nonces existed have no owner and are visible to nobody. |
| **Token guessing** | Failed attempts are counted per IP. After `RATE_AUTH_FAILS_PER_MIN` (10) the IP gets 429 for a minute, even with the right token. |
| **Rate limits per IP** | `RATE_API_PER_MIN` (120) for all API calls. `RATE_SCANS_PER_HOUR` (6) for new scans, which are the expensive ones. The response is 429 with `Retry-After`. |
| **Real client IP** | Set `TRUST_PROXY_HEADERS=1` behind Caddy. The limiter then uses the last `X-Forwarded-For` entry. It is off by default so clients can't spoof it. |
| **Concurrency** | `LIMIT_MAX_CONCURRENT` running and `LIMIT_MAX_QUEUED` waiting; more gets 429 (see [limits-and-lifecycle.md](limits-and-lifecycle.md)). |
| **Input validation** | The source must be an npm name, optionally with a version, or an `https://` URL on github.com, gitlab.com or bitbucket.org. It can't start with `-` and is at most 300 characters, so it can't smuggle options into `npm` or `git`. |
| **Uploads** | Only `.tgz`, `.tar.gz`, `.tar` and `.zip`, checked against the file's magic bytes. A safe file name. At most `MAX_UPLOAD_MB` (25), enforced on `Content-Length` and again while streaming for chunked bodies (413). |
| **Request timeouts** | A client has `BODY_READ_TIMEOUT` seconds (30) per body chunk, so a slow upload gets 408. uvicorn drops idle keep-alives after 5s and caps simultaneous connections at 100. |
| **No leaked internals** | Unhandled errors return `internal error (ref xxxx)`. Failed scans show a short message, or a clean worker reason such as "npm package not found". Tracebacks, paths and worker output go to the server log only, tagged with the same ref. `/docs`, `/redoc` and `/openapi.json` are disabled and the server header is off. |

## Set it up

```bash
openssl rand -hex 24                 # put the result in .env as APP_TOKEN=...
# production (parivant.se): add APP_TOKEN and TRUST_PROXY_HEADERS=1 to /root/vulture/.env, then redeploy
```

Leave `APP_TOKEN` empty to run open: anyone who can reach the API can start scans and spend your credits, limited only by the rate limits. Set it before sharing the URL or turning on `SANDBOX_MODE=vultr`. The deploy check expects 401 without the token and 200 with it when a token is set, and 200 when none is.

Call the API from a script:

```bash
NONCE=$(curl -s -X POST -H "Authorization: Bearer $APP_TOKEN" https://parivant.se/api/nonce | jq -r .nonce)   # once; keep it
curl -H "Authorization: Bearer $APP_TOKEN" -H "X-Vulture-Nonce: $NONCE" -F source=left-pad@1.3.0 https://parivant.se/api/scans
```

## Known limits

- `APP_TOKEN` is still shared (it gates the instance); the personal nonce separates users' data. A nonce can't be recovered or reset: lose it and those scans are unreachable, share it and the sharer gives access. It is a bearer secret, not a login, so send it only over TLS.
- `GET /api/limits` and `POST /api/nonce` need the token but no nonce.
- Rate-limit counters are in memory and reset on restart. That's fine for a single API process.
- WebSocket auth belongs to Part 3. Browsers can't set headers on a WebSocket, so use a first message or a short-lived ticket.

## Tests

`cd api && python3 -m unittest discover tests` (needs `fastapi` and `httpx`). They cover auth, per-user nonce isolation (`tests/test_nonce.py`), token-guess lockout, scan rate limit, source and upload validation, the 413 size cap, error redaction and open mode without a token.
