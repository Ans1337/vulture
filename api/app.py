"""Vulture MVP API: start a scan, poll its progress, read the report. Serves the web UI."""
from __future__ import annotations

import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles

import analyze
import orchestrator

app = FastAPI(title="Vulture")
SCANS: dict[str, dict] = {}   # MVP: in memory
MAX_UPLOAD = 50 * 1024 * 1024
STAGES = ["fetch", "static", "sandbox", "detonate", "observe", "analyze"]


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
async def create_scan(source: str = Form(""), file: Optional[UploadFile] = File(None)):
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
    sid = uuid.uuid4().hex[:10]
    scan = {"id": sid, "source": source, "status": "queued", "stage": None, "created": time.time(),
            "events": [], "report": None, "error": None}
    SCANS[sid] = scan
    threading.Thread(target=_run, args=(scan, upload), daemon=True).start()
    return {"id": sid}


@app.get("/api/scans")
def list_scans():
    return [{k: s[k] for k in ("id", "source", "status", "created")} | {"verdict": (s["report"] or {}).get("verdict")}
            for s in sorted(SCANS.values(), key=lambda s: -s["created"])]


@app.get("/api/scans/{sid}")
def get_scan(sid: str):
    if sid not in SCANS:
        raise HTTPException(404)
    return SCANS[sid] | {"stages": STAGES}


app.mount("/", StaticFiles(directory=Path(__file__).parent.parent / "dashboard", html=True), name="ui")
