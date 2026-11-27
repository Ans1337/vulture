# Part 1: lock-down

The public site can't be used to run arbitrary code on our VM or to burn AI credits.
The code is in [`api/security.py`](../api/security.py).

| Protection | How |
|---|---|
| **Access token** | `APP_TOKEN` is required. The API refuses to start without one (the minimum length is 16 characters). Every `/api/*` call needs `Authorization: Bearer <token>` or `X-Vulture-Token`. The check is constant-time. The dashboard HTML stays public. It asks for the token once, stores it in the browser and asks again on a 401. |
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

`./start.sh` generates a token into `.env` if there is none. **The deploy fails until `APP_TOKEN` is in the production `.env`**, because the API won't start without it. The health checks in CI and in `infra/deploy-main.sh` now check that the API answers 401 without the token and 200 with it.

Call the API from a script:

```bash
curl -H "Authorization: Bearer $APP_TOKEN" -F source=left-pad@1.3.0 https://parivant.se/api/scans
```

## Known limits

- The token is shared, so there is no per-user identity yet. Part 8's audit log will only be able to record "token holder".
- Rate-limit counters are in memory and reset on restart. That's fine for a single API process.
- WebSocket auth belongs to Part 3. Browsers can't set headers on a WebSocket, so use a first message or a short-lived ticket.

## Tests

`cd api && python3 -m unittest discover tests` (needs `fastapi` and `httpx`). They cover auth, token-guess lockout, scan rate limit, source and upload validation, the 413 size cap, error redaction and the refusal to start without a token.
