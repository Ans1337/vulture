"""Vulture MVP API: start a scan, poll its progress, read the report. Serves the web UI."""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles

import analyze
import orchestrator

app = FastAPI(title="Vulture")
SCANS: dict[str, dict] = {}   # MVP: in memory
MAX_UPLOAD = 50 * 1024 * 1024
STAGES = ["fetch", "static", "sandbox", "detonate", "observe", "analyze"]

# Same rules as parse_source() in sandbox-images/worker/common.py (the worker re-checks): npm name
# (lowercase, url-safe, optional @scope/) + optional exact version or dist-tag, or a GitHub repo URL.
NPM_RE = re.compile(r"^(?:npm:)?((?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*)"
                    r"(?:@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?|[A-Za-z0-9][A-Za-z0-9._-]*))?$")
GITHUB_RE = re.compile(r"^https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100}?)"
                       r"(?:\.git)?/?(?:#([A-Za-z0-9._][A-Za-z0-9._/-]{0,199}))?$")


def valid_source(src: str) -> bool:
    m = NPM_RE.fullmatch(src)
    if m and len(m.group(1)) <= 214:
        return True
    m = GITHUB_RE.fullmatch(src)
    return bool(m) and m.group(2) not in (".", "..") and ".." not in (m.group(3) or "")


# Personal nonce: each user keeps a secret nonce and sends it as X-Vulture-Nonce. A scan is owned by the SHA-256
# of the nonce that created it (the nonce itself is never stored) and is invisible without it.
NONCE_RE = re.compile(r"[A-Za-z0-9_-]{32,128}")


def current_owner(x_vulture_nonce: str = Header("")) -> str:
    if not NONCE_RE.fullmatch(x_vulture_nonce):
        raise HTTPException(401, "missing or invalid personal nonce (send X-Vulture-Nonce; get one from POST /api/nonce)")
    return hashlib.sha256(x_vulture_nonce.encode()).hexdigest()


def own_scan(sid: str, owner: str) -> dict:
    """404 both for missing scans and for someone else's, so ids can't be probed."""
    scan = SCANS.get(sid)
    if not scan or not hmac.compare_digest(scan["owner"], owner):
        raise HTTPException(404, "no such scan")
    return scan


def _run(scan: dict, upload: Optional[tuple[str, bytes]]):
    def emit(stage, msg, data):
        scan["stage"] = stage
        scan["events"].append({"t": round(time.time() - scan["created"], 1), "stage": stage, "msg": msg,
                               "data": data})
    try:
        scan["status"] = "running"
        raw = orchestrator.run_scan(scan["id"], scan["source"], upload, emit)
        emit("analyze", "agent reviewing traces + dormant code", {})
        scan["report"] = analyze.report(raw)
        emit("analyze", f"verdict: {scan['report']['verdict'].upper()}", {})
        scan["status"] = "done"
    except Exception as e:
        traceback.print_exc()
        scan["status"] = "failed"
        scan["error"] = str(e)[:1000]


@app.post("/api/scans", status_code=201)
async def create_scan(source: str = Form(""), file: Optional[UploadFile] = File(None),
                      owner: str = Depends(current_owner)):
    upload = None
    if file is not None and file.filename:
        data = await file.read(MAX_UPLOAD + 1)
        if len(data) > MAX_UPLOAD:
            raise HTTPException(413, "upload too large (50 MB max)")
        upload = (file.filename, data)
        source = f"upload:{file.filename}"
    source = source.strip()
    if not source:
        raise HTTPException(400, "give an npm package name, a GitHub URL, or upload a file")
    if upload is None and not valid_source(source):
        raise HTTPException(400, "unsupported source: give an npm package name (name, @scope/name, name@1.2.3, "
                                 "name@latest), a GitHub URL (https://github.com/owner/repo[#ref]), or upload a file")
    sid = uuid.uuid4().hex[:10]
    scan = {"id": sid, "source": source, "status": "queued", "stage": None, "created": time.time(),
            "events": [], "report": None, "error": None, "owner": owner}
    SCANS[sid] = scan
    threading.Thread(target=_run, args=(scan, upload), daemon=True).start()
    return {"id": sid}


@app.post("/api/nonce")
def issue_nonce():
    """Mint a personal nonce (256 random bits). Nothing is stored; it becomes an identity when a scan is created
    with it. It can't be recovered or reset, so the client must keep it."""
    return {"nonce": secrets.token_urlsafe(32)}


@app.get("/api/scans")
def list_scans(owner: str = Depends(current_owner)):
    mine = (s for s in SCANS.values() if hmac.compare_digest(s["owner"], owner))
    return [{k: s[k] for k in ("id", "source", "status", "created")} | {"verdict": (s["report"] or {}).get("verdict")}
            for s in sorted(mine, key=lambda s: -s["created"])]


@app.get("/api/scans/{sid}")
def get_scan(sid: str, owner: str = Depends(current_owner)):
    scan = own_scan(sid, owner)
    return {k: v for k, v in scan.items() if k != "owner"} | {"stages": STAGES}


app.mount("/", StaticFiles(directory=Path(__file__).parent.parent / "dashboard", html=True), name="ui")
