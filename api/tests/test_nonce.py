"""Personal nonce: users can't see each other's scans. Run: cd api && python -m unittest discover tests (needs fastapi + httpx)."""
import os, sys, unittest
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from fastapi.testclient import TestClient
import app as appmod

ALICE = {"X-Vulture-Nonce": "a" * 43}
BOB = {"X-Vulture-Nonce": "b" * 43}


class NonceTest(unittest.TestCase):
    def setUp(self):
        appmod.SCANS.clear()
        p = mock.patch.object(appmod.orchestrator, "run_scan", side_effect=RuntimeError("stop"))
        p.start(); self.addCleanup(p.stop)
        self.c = TestClient(appmod.app, raise_server_exceptions=False)

    def scan(self, h):
        return self.c.post("/api/scans", data={"source": "left-pad"}, headers=h)

    def test_nonce_required_and_validated(self):
        for h in ({}, {"X-Vulture-Nonce": "short"}, {"X-Vulture-Nonce": "!" * 40}):
            self.assertEqual(self.c.get("/api/scans", headers=h).status_code, 401)
            self.assertEqual(self.scan(h).status_code, 401)

    def test_issued_nonces_are_valid_and_unique(self):
        a, b = (self.c.post("/api/nonce").json()["nonce"] for _ in range(2))
        self.assertNotEqual(a, b)
        self.assertEqual(self.c.get("/api/scans", headers={"X-Vulture-Nonce": a}).status_code, 200)

    def test_users_cannot_see_each_others_scans(self):
        sid = self.scan(ALICE).json()["id"]
        self.assertEqual(self.c.get(f"/api/scans/{sid}", headers=ALICE).status_code, 200)
        self.assertEqual([s["id"] for s in self.c.get("/api/scans", headers=ALICE).json()], [sid])
        self.assertEqual(self.c.get("/api/scans", headers=BOB).json(), [])
        other = self.c.get(f"/api/scans/{sid}", headers=BOB)
        missing = self.c.get("/api/scans/nope", headers=BOB)
        self.assertEqual(other.status_code, 404)
        self.assertEqual(other.json(), missing.json())      # indistinguishable from a scan that doesn't exist

    def test_one_wrong_character_gets_nothing(self):
        sid = self.scan(ALICE).json()["id"]
        self.assertEqual(self.c.get(f"/api/scans/{sid}", headers={"X-Vulture-Nonce": "a" * 42 + "x"}).status_code, 404)

    def test_only_a_hash_is_kept_and_it_is_never_returned(self):
        sid = self.scan(ALICE).json()["id"]
        self.assertNotIn("owner", self.c.get(f"/api/scans/{sid}", headers=ALICE).json())
        self.assertEqual(appmod.SCANS[sid]["owner"], appmod.hashlib.sha256(b"a" * 43).hexdigest())


if __name__ == "__main__":
    unittest.main()
