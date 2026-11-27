"""Part 1: lock-down. Token auth, per-IP rate limits, request size/time limits, input validation.

All of it is plain ASGI middleware plus a few helpers, configured from the environment:

  APP_TOKEN              optional. When set, every /api/* request must send it (Authorization: Bearer ... or
                         X-Vulture-Token). When empty the API is open (a warning is logged at startup).
  TRUST_PROXY_HEADERS    1 when behind Caddy/nginx: the client IP is the last X-Forwarded-For entry.
  RATE_API_PER_MIN       all /api/* requests per IP per minute            (default 120)
  RATE_SCANS_PER_HOUR    new scans per IP per hour                        (default 6)
  RATE_AUTH_FAILS_PER_MIN  failed token attempts per IP per minute        (default 10)
  Personal nonce         separate from APP_TOKEN: each user keeps their own secret nonce (X-Vulture-Nonce header,
                         issued by POST /api/nonce). Scans are owned by it and invisible without it. Only its
                         SHA-256 is stored.
  MAX_UPLOAD_MB          upload limit                                     (default 25)
  BODY_READ_TIMEOUT      seconds a client gets to send the request body   (default 30)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque

log = logging.getLogger("vulture.security")


def _int(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, "") or default))
    except ValueError:
        raise SystemExit(f"{name} must be an integer")


APP_TOKEN = os.environ.get("APP_TOKEN", "").strip()
TRUST_PROXY = os.environ.get("TRUST_PROXY_HEADERS", "") == "1"
RATE_API = _int("RATE_API_PER_MIN", 120)
RATE_SCANS = _int("RATE_SCANS_PER_HOUR", 6)
RATE_FAILS = _int("RATE_AUTH_FAILS_PER_MIN", 10)
MAX_UPLOAD = _int("MAX_UPLOAD_MB", 25) * 1024 * 1024
BODY_TIMEOUT = _int("BODY_READ_TIMEOUT", 30)
MAX_FORM_OVERHEAD = 64 * 1024   # multipart boundaries + the source field

if not APP_TOKEN:
    log.warning("APP_TOKEN is not set: the API is OPEN to anyone who can reach it. Rate limits still apply. "
                "Set APP_TOKEN in .env (openssl rand -hex 24) to lock it.")
if APP_TOKEN and len(APP_TOKEN) < 16:
    raise SystemExit("APP_TOKEN is too short (min 16 chars). Try: openssl rand -hex 24")


class RateLimiter:
    """Sliding window per key. In memory, which is fine for one API process."""

    def __init__(self):
        self.hits: dict[str, deque] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float) -> tuple[bool, int]:
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False, int(q[0] + window - now) + 1
            q.append(now)
            if len(self.hits) > 10_000:   # bound memory: drop idle keys
                for k in [k for k, v in self.hits.items() if not v or v[-1] <= now - 3600]:
                    del self.hits[k]
            return True, 0

    def count(self, key: str, window: float) -> int:
        now = time.monotonic()
        with self.lock:
            q = self.hits.get(key)
            return sum(1 for t in q if t > now - window) if q else 0


LIMITER = RateLimiter()


def client_ip(scope) -> str:
    if TRUST_PROXY:
        for k, v in scope.get("headers", []):
            if k == b"x-forwarded-for":
                last = v.decode("latin-1").split(",")[-1].strip()
                if last:
                    return last
    c = scope.get("client")
    return c[0] if c else "unknown"


def _token_ok(scope) -> bool:
    if not APP_TOKEN:
        return True
    given = ""
    for k, v in scope.get("headers", []):
        if k == b"authorization" and v[:7].lower() == b"bearer ":
            given = v[7:].decode("latin-1").strip()
        elif k == b"x-vulture-token":
            given = v.decode("latin-1").strip()
    return hmac.compare_digest(given.encode(), APP_TOKEN.encode())


# ---- personal nonce ---------------------------------------------------------------------------

NONCE_RE = re.compile(r"[A-Za-z0-9_-]{32,128}")


def new_nonce() -> str:
    return secrets.token_urlsafe(32)   # 256 bits


def valid_nonce(nonce: str) -> bool:
    return bool(NONCE_RE.fullmatch(nonce or ""))


def nonce_hash(nonce: str) -> str:
    """What gets stored. The nonce itself is high-entropy, so a plain SHA-256 is enough; a database leak
    does not let anyone act as a user."""
    return hashlib.sha256(nonce.encode()).hexdigest()


async def _send_json(send, status: int, detail: str, headers: list | None = None):
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                            (b"cache-control", b"no-store"), *(headers or [])]})
    await send({"type": "http.response.body", "body": body})


class LockDown:
    """Outermost middleware for /api/*: auth, rate limits, body size cap, body read timeout."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope["path"].startswith("/api/"):
            return await self.app(scope, receive, send)   # static dashboard needs no token; it asks for one
        ip = client_ip(scope)
        method = scope["method"]

        # Brute-force guard first: an IP that keeps guessing tokens is cut off before any compare.
        if RATE_FAILS <= LIMITER.count(f"fail:{ip}", 60):
            return await _send_json(send, 429, "too many failed attempts; wait a minute",
                                    [(b"retry-after", b"60")])
        if not _token_ok(scope):
            LIMITER.allow(f"fail:{ip}", 10**9, 60)
            log.warning("rejected request without a valid token from %s: %s %s", ip, method, scope["path"])
            return await _send_json(send, 401, "missing or invalid access token",
                                    [(b"www-authenticate", b"Bearer")])

        ok, wait = LIMITER.allow(f"api:{ip}", RATE_API, 60)
        if ok and method == "POST" and scope["path"] == "/api/scans":
            ok, wait = LIMITER.allow(f"scan:{ip}", RATE_SCANS, 3600)
        if not ok:
            return await _send_json(send, 429, "rate limit reached; slow down",
                                    [(b"retry-after", str(wait).encode())])

        if method in ("POST", "PUT", "PATCH"):
            cap = MAX_UPLOAD + MAX_FORM_OVERHEAD
            for k, v in scope["headers"]:
                if k == b"content-length":
                    try:
                        if int(v) > cap:
                            return await _send_json(send, 413, f"request too large ({MAX_UPLOAD >> 20} MB max)")
                    except ValueError:
                        return await _send_json(send, 400, "bad content-length")
            seen = 0

            async def guarded_receive():
                nonlocal seen
                try:
                    msg = await asyncio.wait_for(receive(), BODY_TIMEOUT)   # slow-loris guard
                except asyncio.TimeoutError:
                    raise RequestAborted(408, "timed out sending the request")
                if msg["type"] == "http.request":
                    seen += len(msg.get("body", b""))
                    if seen > cap:   # chunked uploads have no content-length
                        raise RequestAborted(413, f"request too large ({MAX_UPLOAD >> 20} MB max)")
                return msg

            started = False

            async def tracking_send(m):
                nonlocal started
                started = started or m["type"] == "http.response.start"
                await send(m)

            try:
                return await self.app(scope, guarded_receive, tracking_send)
            except RequestAborted as e:
                if not started:
                    return await _send_json(send, e.status, e.detail)
                raise
        return await self.app(scope, receive, send)


class RequestAborted(Exception):
    def __init__(self, status: int, detail: str):
        self.status, self.detail = status, detail


# ---- input validation -------------------------------------------------------------------------

ALLOWED_UPLOAD = (".tgz", ".tar.gz", ".tar", ".zip")


def check_upload(filename: str, data: bytes) -> str | None:
    """Returns an error message, or None if the file looks like a real archive of an allowed type."""
    name = os.path.basename(filename).lower()
    if not name.endswith(ALLOWED_UPLOAD):
        return "unsupported file type; upload a .tgz, .tar.gz, .tar or .zip"
    if len(name) > 120 or not re.match(r"^[\w.@+ -]+$", os.path.basename(filename)):
        return "unsupported file name"
    if not data:
        return "empty file"
    if name.endswith(".zip"):
        magic = data[:4] in (b"PK\x03\x04", b"PK\x05\x06")
    elif name.endswith(".tar"):
        magic = data[257:262] == b"ustar"
    else:
        magic = data[:2] == b"\x1f\x8b"
    return None if magic else "file contents don't match its extension"
