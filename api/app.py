"""Vulture API: start a scan, poll its progress, read the report. Serves the web UI.

Scans, events, reports and raw evidence live in SQLite (store.py), so history survives redeploys.
"""
from __future__ import annotations

import re
import logging
import os
import threading
import time
import traceback
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

import analyze
import lifecycle
import orchestrator
import security
import store
from limits import LIMITS as L

log = logging.getLogger("vulture.api")
SLOTS = threading.BoundedSemaphore(L.max_concurrent)    # scans running at once; the rest wait as "queued"
CANCELS: dict[str, threading.Event] = {}                # live scans only
STAGES = ["fetch", "static", "sandbox", "detonate", "observe", "investigate", "destroy", "analyze"]
SANDBOX_MODE = os.environ.get("SANDBOX_MODE", "docker")  # docker | vultr

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


def _live() -> set[str]:
    return set(CANCELS)


@asynccontextmanager
async def lifespan(_app):
    interrupted = store.init()
    if interrupted:
        log.warning("marked %d interrupted scan(s) as failed", interrupted)
    # After a restart nothing is live, so any leftover sandbox container/network/volume/VM is an orphan.
    stop = lifecycle.start_reaper(_live, L.orphan_max_age)
    if SANDBOX_MODE == "vultr":
        threading.Thread(target=_vm_janitor, args=(stop,), daemon=True, name="vulture-vm-janitor").start()
    yield
    stop.set()


def _vm_janitor(stop: threading.Event):
    """Orphaned throwaway VMs cost money: destroy any tagged instance that belongs to no live scan."""
    import vultr
    first = True
    while not stop.is_set():
        try:
            vultr.janitor(vultr.Vultr(), _live(), 0 if first else int(os.environ.get("VULTR_VM_MAX_AGE", "3600")))
        except Exception:
            log.exception("VM janitor pass failed")
        first = False
        stop.wait(300)


app = FastAPI(title="Vulture", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.exception_handler(Exception)
async def hide_internals(_req: Request, exc: Exception):
    ref = uuid.uuid4().hex[:8]
    log.error("unhandled error [%s]", ref, exc_info=exc)
    return JSONResponse({"detail": f"internal error (ref {ref})"}, status_code=500)


def _fail_message(e: Exception) -> str:
    """Full detail goes to the server log only. Users get a short message, never paths or worker output."""
    if isinstance(e, orchestrator.UserFacingError):
        return str(e)[:300]
    if isinstance(e, TimeoutError):
        return "the scan ran past its time limit and was stopped"
    return f"the scan failed internally (ref {uuid.uuid4().hex[:8]})"


def _run(scan_id: str, source: str, upload: Optional[tuple[str, bytes]], cancel: threading.Event):
    t0 = store.get(scan_id)["created"]

    def emit(stage, msg, data):
        store.add_event(scan_id, round(time.time() - t0, 1), stage, msg, data)
        if stage == "destroy" and "lifecycle" in data:
            store.set_status(scan_id, "running", lifecycle=data["lifecycle"])

    try:
        while not SLOTS.acquire(timeout=1):          # queued: wait for a sandbox slot, but stay cancellable
            if cancel.is_set():
                raise orchestrator.Cancelled()
        try:
            if cancel.is_set():
                raise orchestrator.Cancelled()
            store.set_status(scan_id, "running")
            raw = orchestrator.run_scan(scan_id, source, upload, emit, cancel=cancel, mode=SANDBOX_MODE)
        finally:
            SLOTS.release()
        store.save_evidence(scan_id, raw)
        emit("analyze", "agent reviewing traces + dormant code", {})
        rep = analyze.report(raw)
        emit("analyze", f"verdict: {rep['verdict'].upper()}", {})
        store.set_status(scan_id, "done", report=rep, verdict=rep["verdict"], finished=time.time())
    except orchestrator.Cancelled:
        store.set_status(scan_id, "cancelled", error="cancelled by user", finished=time.time())
    except Exception as e:
        log.error("scan %s failed\n%s", scan_id, traceback.format_exc())
        store.set_status(scan_id, "cancelled" if cancel.is_set() else "failed",
                         error="cancelled by user" if cancel.is_set() else _fail_message(e), finished=time.time())
    finally:
        CANCELS.pop(scan_id, None)
        store.prune(L.history_max)


@app.post("/api/scans", status_code=201)
async def create_scan(source: str = Form(""), force: bool = Form(False), file: Optional[UploadFile] = File(None)):
    upload = None
    if file is not None and file.filename:
        data = await file.read(security.MAX_UPLOAD + 1)
        if len(data) > security.MAX_UPLOAD:
            raise HTTPException(413, f"upload too large ({security.MAX_UPLOAD >> 20} MB max)")
        bad = security.check_upload(file.filename, data)
        if bad:
            raise HTTPException(400, bad)
        upload = (os.path.basename(file.filename), data)
        source = f"upload:{upload[0]}"
    source = source.strip()
    if not source:
        raise HTTPException(400, "give an npm package name, a GitHub URL, or upload a file")
    if upload is None and not valid_source(source):
        raise HTTPException(400, "unsupported source: give an npm package name (name, @scope/name, name@1.2.3, "
                                 "name@latest), a GitHub URL (https://github.com/owner/repo[#ref]), or upload a file")
    # Dedupe: an exact version/commit that was already scanned has the same answer. force=true re-scans.
    key = None if upload else store.source_key(source)
    if key and not force and (prev := store.find_done(key)):
        return JSONResponse({"id": prev, "deduped": True}, status_code=200)
    if store.counts().get("queued", 0) >= L.max_queued:
        raise HTTPException(429, f"scan queue is full ({L.max_queued} waiting); try again shortly")
    sid = uuid.uuid4().hex[:10]
    store.create(sid, source, SANDBOX_MODE)
    cancel = CANCELS[sid] = threading.Event()
    threading.Thread(target=_run, args=(sid, source, upload, cancel), daemon=True).start()
    return {"id": sid}


@app.get("/api/limits")
def limits():
    """The caps every sandbox run is held to."""
    return L.as_dict() | {"sandbox_mode": SANDBOX_MODE}


@app.get("/api/scans")
def list_scans(q: str = "", status: str = "", verdict: str = "", limit: int = Query(100, ge=1, le=500)):
    return store.list_scans(q=q, status=status, verdict=verdict, limit=limit)


@app.get("/api/scans/{sid}")
def get_scan(sid: str, after: int = Query(0, ge=0)):
    """`after` = last event id the client has, so polling only transfers new events."""
    s = store.get(sid, after)
    if not s:
        raise HTTPException(404, "no such scan")
    return s | {"stages": STAGES}


@app.get("/api/scans/{sid}/evidence")
def get_evidence(sid: str):
    raw = store.get_evidence(sid)
    if raw is None:
        raise HTTPException(404, "no evidence stored for this scan")
    return raw


@app.post("/api/scans/{sid}/cancel")
def cancel_scan(sid: str):
    ev = CANCELS.get(sid)
    if ev is None:
        if store.get(sid) is None:
            raise HTTPException(404, "no such scan")
        raise HTTPException(409, "scan is not running")
    ev.set()                                          # the worker thread stops and tears everything down
    return {"id": sid, "cancelling": True}


@app.post("/api/scans/{sid}/reanalyze")
def reanalyze(sid: str):
    """Re-run stage 6 on the stored raw evidence (new rules or model) without detonating again."""
    s = store.get(sid)
    raw = store.get_evidence(sid)
    if not s or raw is None:
        raise HTTPException(404, "no stored evidence for this scan")
    rep = analyze.report(raw)
    store.set_status(sid, "done", _override=True, report=rep, verdict=rep["verdict"])
    return {"id": sid, "verdict": rep["verdict"]}


app.add_middleware(security.LockDown)
app.mount("/", StaticFiles(directory=Path(__file__).resolve().parent.parent / "dashboard", html=True), name="ui")
