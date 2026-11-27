"""Run: cd api && python -m unittest discover tests  (needs fastapi + httpx; no Docker)."""
import io, os, sys, tempfile, unittest
from unittest import mock

os.environ.update(VULTURE_DB=os.path.join(tempfile.mkdtemp(), "t.db"), APP_TOKEN="t" * 32, RATE_AUTH_FAILS_PER_MIN="4",
                  RATE_API_PER_MIN="1000", MAX_UPLOAD_MB="1", LIMIT_MAX_QUEUED="50")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fastapi.testclient import TestClient
import app as appmod, security, store

H = {"Authorization": "Bearer " + "t" * 32}


class SecurityTest(unittest.TestCase):
    def setUp(self):
        security.LIMITER.hits.clear()
        security.RATE_SCANS = 1000
        if os.path.exists(store.DB_PATH): os.remove(store.DB_PATH)
        store.init()
        p = mock.patch.object(appmod.orchestrator, "run_scan", side_effect=RuntimeError("boom /srv/secret/path"))
        p.start(); self.addCleanup(p.stop)
        self.c = TestClient(appmod.app, raise_server_exceptions=False)

    def test_static_ui_is_public_api_is_not(self):
        self.assertEqual(self.c.get("/").status_code, 200)
        self.assertEqual(self.c.get("/api/scans").status_code, 401)
        self.assertEqual(self.c.get("/api/scans", headers={"Authorization": "Bearer nope"}).status_code, 401)
        self.assertEqual(self.c.get("/api/scans", headers=H).status_code, 200)
        self.assertEqual(self.c.get("/api/scans", headers={"X-Vulture-Token": "t" * 32}).status_code, 200)

    def test_docs_and_openapi_hidden(self):
        for path in ("/docs", "/redoc", "/openapi.json"):
            self.assertNotEqual(self.c.get(path, headers=H).status_code, 200)

    def test_token_guessing_is_cut_off(self):
        codes = [self.c.get("/api/scans", headers={"Authorization": "Bearer x"}).status_code for _ in range(6)]
        self.assertEqual(codes[:4], [401] * 4)
        self.assertEqual(codes[4], 429)
        self.assertEqual(self.c.get("/api/scans", headers=H).status_code, 429)   # even the right token waits

    def test_scan_creation_rate_limited(self):
        security.RATE_SCANS = 3
        codes = [self.c.post("/api/scans", data={"source": "left-pad"}, headers=H).status_code for _ in range(4)]
        self.assertEqual(codes, [201, 201, 201, 429])

    def test_source_validation(self):
        for bad in ["--registry=http://evil", "-x", "a b", "http://github.com/a/b", "https://evil.com/a/b", "https://gitlab.com/a/b",
                    "x" * 400, "left-pad; rm -rf /"]:
            r = self.c.post("/api/scans", data={"source": bad}, headers=H)
            self.assertEqual(r.status_code, 400, bad)
        for ok in ["left-pad", "npm:left-pad@1.3.0", "@scope/pkg", "https://github.com/Ans1337/vulture#main"]:
            security.LIMITER.hits.clear()
            self.assertEqual(self.c.post("/api/scans", data={"source": ok}, headers=H).status_code, 201, ok)

    def test_upload_checks(self):
        def up(name, data):
            return self.c.post("/api/scans", files={"file": (name, io.BytesIO(data))}, headers=H)
        self.assertEqual(up("x.sh", b"#!/bin/sh").status_code, 400)
        self.assertEqual(up("x.tgz", b"not gzip").status_code, 400)
        self.assertEqual(up("x.tgz", b"\x1f\x8b" + b"0" * 10).status_code, 201)
        self.assertEqual(up("big.tgz", b"\x1f\x8b" + b"0" * (2 << 20)).status_code, 413)

    def test_errors_do_not_leak_internals(self):
        sid = self.c.post("/api/scans", data={"source": "left-pad"}, headers=H).json()["id"]
        import time; time.sleep(0.3)
        err = self.c.get(f"/api/scans/{sid}", headers=H).json()["error"]
        self.assertNotIn("/srv", err); self.assertNotIn("boom", err); self.assertIn("ref", err)

    def test_clean_worker_errors_are_shown(self):
        with mock.patch.object(appmod.orchestrator, "run_scan",
                               side_effect=appmod.orchestrator.UserFacingError("npm package not found")):
            sid = self.c.post("/api/scans", data={"source": "nope"}, headers=H).json()["id"]
            import time; time.sleep(0.3)
        self.assertEqual(self.c.get(f"/api/scans/{sid}", headers=H).json()["error"], "npm package not found")

    def test_open_mode_without_token(self):
        import importlib
        try:
            with mock.patch.dict(os.environ, {"APP_TOKEN": ""}):
                importlib.reload(security)
                self.assertEqual(security.APP_TOKEN, "")
                self.assertEqual(self.c.get("/api/scans").status_code, 200)    # open: no token needed
                self.assertEqual(self.c.post("/api/scans", data={"source": "--bad"}).status_code, 400)  # still validated
        finally:
            importlib.reload(security)

if __name__ == "__main__":
    unittest.main()
