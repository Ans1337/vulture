"""Personal nonce: users can't see each other's scans, evidence or reports. Run: cd api && python -m unittest discover tests"""
import os, sys, tempfile, unittest
from unittest import mock

os.environ.update(VULTURE_DB=os.path.join(tempfile.mkdtemp(), "n.db"), APP_TOKEN="t" * 32, RATE_API_PER_MIN="10000",
                  RATE_SCANS_PER_HOUR="10000", LIMIT_MAX_QUEUED="50")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fastapi.testclient import TestClient
import app as appmod, security, store

TOK = {"Authorization": "Bearer " + "t" * 32}
ALICE = TOK | {"X-Vulture-Nonce": "a" * 43}
BOB = TOK | {"X-Vulture-Nonce": "b" * 43}


class NonceTest(unittest.TestCase):
    def setUp(self):
        security.LIMITER.hits.clear()
        if os.path.exists(store.DB_PATH): os.remove(store.DB_PATH)
        store.init()
        p = mock.patch.object(appmod.orchestrator, "run_scan", return_value={"marker": "M"})
        p.start(); self.addCleanup(p.stop)
        self.c = TestClient(appmod.app, raise_server_exceptions=False)

    def scan(self, h, src="left-pad@1.3.0", **kw):
        return self.c.post("/api/scans", data={"source": src, **kw}, headers=h)

    def test_nonce_required_and_validated(self):
        for h in (TOK, TOK | {"X-Vulture-Nonce": "short"}, TOK | {"X-Vulture-Nonce": "!" * 40}):
            self.assertEqual(self.scan(h).status_code, 401)
        for h in (TOK | {"X-Vulture-Nonce": "short"}, TOK | {"X-Vulture-Nonce": "!" * 40}):
            self.assertEqual(self.c.get("/api/scans", headers=h).status_code, 401)

    def test_list_without_nonce_is_empty_not_an_error(self):
        sid = self.scan(ALICE).json()["id"]
        r = self.c.get("/api/scans", headers=TOK)   # what the deploy health check calls
        self.assertEqual((r.status_code, r.json()), (200, []))
        for method, path in [("get", f"/api/scans/{sid}"), ("get", f"/api/scans/{sid}/evidence"),
                             ("post", f"/api/scans/{sid}/cancel"), ("post", f"/api/scans/{sid}/reanalyze")]:
            self.assertEqual(getattr(self.c, method)(path, headers=TOK).status_code, 401, path)

    def test_issued_nonce_is_valid_and_unique(self):
        a = self.c.post("/api/nonce", headers=TOK).json()["nonce"]
        b = self.c.post("/api/nonce", headers=TOK).json()["nonce"]
        self.assertNotEqual(a, b)
        self.assertTrue(security.valid_nonce(a))
        self.assertEqual(self.c.get("/api/scans", headers=TOK | {"X-Vulture-Nonce": a}).status_code, 200)

    def test_nonce_endpoint_still_needs_app_token(self):
        self.assertEqual(self.c.post("/api/nonce").status_code, 401)

    def test_users_cannot_see_each_others_scans(self):
        sid = self.scan(ALICE).json()["id"]
        self.assertEqual(self.c.get(f"/api/scans/{sid}", headers=ALICE).status_code, 200)
        self.assertEqual([s["id"] for s in self.c.get("/api/scans", headers=ALICE).json()], [sid])
        self.assertEqual(self.c.get("/api/scans", headers=BOB).json(), [])
        for method, path in [("get", f"/api/scans/{sid}"), ("get", f"/api/scans/{sid}/evidence"),
                             ("post", f"/api/scans/{sid}/cancel"), ("post", f"/api/scans/{sid}/reanalyze")]:
            other = getattr(self.c, method)(path, headers=BOB)
            missing = getattr(self.c, method)(path.replace(sid, "nope"), headers=BOB)
            self.assertEqual(other.status_code, 404, path)
            self.assertEqual(other.json(), missing.json(), path)   # same answer as a scan that doesn't exist

    def test_wrong_nonce_gets_nothing_even_with_valid_token(self):
        sid = self.scan(ALICE).json()["id"]
        self.assertEqual(self.c.get(f"/api/scans/{sid}", headers=TOK | {"X-Vulture-Nonce": "a" * 42 + "x"}).status_code, 404)

    def test_dedupe_never_crosses_users(self):
        a = self.scan(ALICE).json()["id"]
        self.assertTrue(self._wait_done(a))
        again = self.scan(ALICE)
        self.assertEqual((again.status_code, again.json()), (200, {"id": a, "deduped": True}))
        bobs = self.scan(BOB)
        self.assertEqual(bobs.status_code, 201)
        self.assertNotEqual(bobs.json()["id"], a)

    def test_only_hash_is_stored_and_never_returned(self):
        sid = self.scan(ALICE).json()["id"]
        body = self.c.get(f"/api/scans/{sid}", headers=ALICE).json()
        self.assertNotIn("owner", body)
        with store.conn() as c:
            owner = c.execute("SELECT owner FROM scans WHERE id=?", (sid,)).fetchone()["owner"]
        self.assertEqual(owner, security.nonce_hash("a" * 43))
        self.assertNotIn("a" * 43, owner)

    def test_legacy_scans_without_owner_are_invisible(self):
        store.create("old1", "left-pad", "docker")   # owner NULL, like rows from before nonces
        self.assertEqual(self.c.get("/api/scans", headers=ALICE).json(), [])
        self.assertEqual(self.c.get("/api/scans/old1", headers=ALICE).status_code, 404)

    def test_migration_adds_owner_column(self):
        import sqlite3
        os.remove(store.DB_PATH)
        c = sqlite3.connect(store.DB_PATH)
        c.executescript("""CREATE TABLE scans(id TEXT PRIMARY KEY, source TEXT NOT NULL, source_key TEXT, status TEXT NOT NULL,
            stage TEXT, created REAL NOT NULL, finished REAL, error TEXT, verdict TEXT, report TEXT, lifecycle TEXT, mode TEXT);
            INSERT INTO scans(id,source,status,created) VALUES('legacy','x','done',1.0);""")
        c.commit(); c.close()
        store.init()
        self.assertEqual(store.list_scans(owner="anyone"), [])
        self.assertEqual(len(store.list_scans()), 1)

    def _wait_done(self, sid, t=3):
        import time
        end = time.time() + t
        while time.time() < end:
            if store.status_of(sid) == "done": return True
            time.sleep(0.05)
        return False


if __name__ == "__main__":
    unittest.main()
