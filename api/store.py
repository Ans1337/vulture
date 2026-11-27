"""Part 2: persistent storage. SQLite (stdlib), WAL mode, one short-lived connection per call.

Tables: scans (one row per scan, incl. report + lifecycle), events (the timeline, in order),
evidence (raw sandbox output, kept so a scan can be re-analysed without re-detonating).
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = os.environ.get("VULTURE_DB", "/data/vulture.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id TEXT PRIMARY KEY, source TEXT NOT NULL, source_key TEXT, status TEXT NOT NULL, stage TEXT,
  created REAL NOT NULL, finished REAL, error TEXT, verdict TEXT, report TEXT, lifecycle TEXT, mode TEXT);
CREATE INDEX IF NOT EXISTS scans_created ON scans(created DESC);
CREATE INDEX IF NOT EXISTS scans_key ON scans(source_key, status);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  t REAL NOT NULL, stage TEXT NOT NULL, msg TEXT NOT NULL, data TEXT);
CREATE INDEX IF NOT EXISTS events_scan ON events(scan_id, id);
CREATE TABLE IF NOT EXISTS evidence(
  scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE, raw TEXT NOT NULL);
"""

_SEMVER = re.compile(r"^(?:npm:)?(@[^/@]+/)?[^/@]+@\d+\.\d+\.\d+(?:[-+][\w.+-]+)?$")
_GIT_SHA = re.compile(r"^(https://[^#]+?)(?:\.git)?/?#([0-9a-f]{40})$")


def source_key(source: str) -> str | None:
    """A key only for sources that pin an exact version/commit, so "left-pad@1.3.0" dedupes but "left-pad" never does."""
    s = source.strip()
    if _SEMVER.match(s):
        return "npm:" + s.removeprefix("npm:").lower()
    m = _GIT_SHA.match(s)
    return f"git:{m.group(1).lower()}#{m.group(2)}" if m else None


@contextmanager
def conn():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    try:
        with c:
            yield c
    finally:
        c.close()


def init() -> int:
    """Create tables; scans that a restart interrupted can never finish, so mark them failed."""
    with conn() as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        now = time.time()
        rows = c.execute("SELECT id FROM scans WHERE status IN ('queued','running')").fetchall()
        for r in rows:
            c.execute("UPDATE scans SET status='failed', finished=?, error=? WHERE id=?",
                      (now, "interrupted by a server restart; submit it again", r["id"]))
            c.execute("INSERT INTO events(scan_id,t,stage,msg,data) VALUES(?,?,?,?,?)",
                      (r["id"], 0, "destroy", "scan interrupted by a server restart", "{}"))
        return len(rows)


def create(scan_id: str, source: str, mode: str) -> dict:
    now = time.time()
    with conn() as c:
        c.execute("INSERT INTO scans(id,source,source_key,status,created,mode) VALUES(?,?,?,?,?,?)",
                  (scan_id, source, source_key(source), "queued", now, mode))
    return {"id": scan_id, "created": now}


def find_done(key: str) -> str | None:
    with conn() as c:
        r = c.execute("SELECT id FROM scans WHERE source_key=? AND status='done' ORDER BY created DESC LIMIT 1",
                      (key,)).fetchone()
    return r["id"] if r else None


def set_status(scan_id: str, status: str, _override: bool = False, **fields):
    allowed = {"stage", "error", "verdict", "report", "lifecycle", "finished"}
    sets, vals = ["status=?"], [status]
    for k, v in fields.items():
        assert k in allowed, k
        sets.append(f"{k}=?")
        vals.append(json.dumps(v) if k in ("report", "lifecycle") and v is not None else v)
    with conn() as c:
        guard = "" if _override else " AND status NOT IN ('done','failed','cancelled')"   # finished scans stay finished
        c.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id=?{guard}", (*vals, scan_id))


def add_event(scan_id: str, t: float, stage: str, msg: str, data: dict):
    with conn() as c:
        c.execute("INSERT INTO events(scan_id,t,stage,msg,data) VALUES(?,?,?,?,?)",
                  (scan_id, t, stage, msg, json.dumps(data)))
        c.execute("UPDATE scans SET stage=? WHERE id=?", (stage, scan_id))


def save_evidence(scan_id: str, raw: dict):
    with conn() as c:
        c.execute("INSERT OR REPLACE INTO evidence(scan_id,raw) VALUES(?,?)", (scan_id, json.dumps(raw)))


def get_evidence(scan_id: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT raw FROM evidence WHERE scan_id=?", (scan_id,)).fetchone()
    return json.loads(r["raw"]) if r else None


def _row(r) -> dict:
    d = dict(r)
    for k in ("report", "lifecycle"):
        d[k] = json.loads(d[k]) if d.get(k) else None
    d.pop("source_key", None)
    return d


def get(scan_id: str, after_event: int = 0) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not r:
            return None
        ev = c.execute("SELECT id,t,stage,msg,data FROM events WHERE scan_id=? AND id>? ORDER BY id",
                       (scan_id, after_event)).fetchall()
    d = _row(r)
    d["events"] = [{"id": e["id"], "t": e["t"], "stage": e["stage"], "msg": e["msg"],
                    "data": json.loads(e["data"] or "{}")} for e in ev]
    return d


def status_of(scan_id: str) -> str | None:
    with conn() as c:
        r = c.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
    return r["status"] if r else None


def list_scans(q: str = "", status: str = "", verdict: str = "", limit: int = 100) -> list[dict]:
    where, vals = [], []
    if q:
        where.append("source LIKE ? ESCAPE '\\'")
        vals.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if status:
        where.append("status=?"); vals.append(status)
    if verdict:
        where.append("verdict=?"); vals.append(verdict)
    sql = "SELECT id,source,status,stage,created,finished,verdict,error FROM scans"
    if where:
        sql += " WHERE " + " AND ".join(where)
    with conn() as c:
        rows = c.execute(sql + " ORDER BY created DESC LIMIT ?", (*vals, max(1, min(limit, 500)))).fetchall()
    return [dict(r) for r in rows]


def counts() -> dict:
    with conn() as c:
        return {r["status"]: r["n"] for r in c.execute("SELECT status, COUNT(*) n FROM scans GROUP BY status")}


def prune(keep: int):
    """Keep the newest `keep` finished scans; events and evidence go with them (ON DELETE CASCADE)."""
    with conn() as c:
        c.execute("""DELETE FROM scans WHERE status IN ('done','failed','cancelled') AND id NOT IN
                     (SELECT id FROM scans WHERE status IN ('done','failed','cancelled')
                      ORDER BY created DESC LIMIT ?)""", (keep,))
