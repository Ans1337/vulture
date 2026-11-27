"""Run: cd api && python -m unittest discover tests   (no Docker needed; uses fakes)."""
import os, sys, types, unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
try:
    import docker  # noqa: F401
except ImportError:  # keep the tests runnable without the docker SDK installed
    d = types.ModuleType("docker"); d.errors = types.SimpleNamespace(NotFound=type("NotFound", (Exception,), {}))
    sys.modules["docker"] = d

import limits, lifecycle


class Res:
    def __init__(self, name, labels, created="2020-01-01T00:00:00.000Z", stuck=0):
        self.name, self.attrs, self.stuck = name, {"Labels": labels, "Config": {"Labels": labels}, "Created": created, "CreatedAt": created}, stuck
    def remove(self, **_):
        if self.stuck:
            self.stuck -= 1; raise RuntimeError("busy")
        self.gone = True


class FakeClient:
    def __init__(self, items):
        self.items = items
        self.containers = types.SimpleNamespace(list=lambda **k: self._f("c", k))
        self.networks = types.SimpleNamespace(list=lambda **k: self._f("n", k))
        self.volumes = types.SimpleNamespace(list=lambda **k: self._f("v", k))
    def _f(self, kind, k):
        want = k["filters"]["label"]
        return [r for t, r in self.items if t == kind and not getattr(r, "gone", False)
                and (want == lifecycle.LABEL or want == f"{lifecycle.LABEL}={r.attrs['Labels'].get(lifecycle.LABEL)}")]


class LimitsTest(unittest.TestCase):
    def test_defaults_cap_time_and_memory(self):
        L = limits.load()
        self.assertTrue(L.detonate_mem.endswith(("m", "g")))
        self.assertGreater(L.scan_timeout, L.detonate_timeout)
        self.assertGreater(L.scan_timeout, L.fetch_timeout)

    def test_bad_values_rejected(self):
        for k, v in [("LIMIT_DETONATE_MEM", "lots"), ("LIMIT_PIDS", "0"), ("LIMIT_SCAN_TIMEOUT", "x")]:
            with mock.patch.dict(os.environ, {k: v}), self.assertRaises(SystemExit):
                limits.load()


class LifecycleTest(unittest.TestCase):
    def test_teardown_removes_everything_and_verifies(self):
        lab = {lifecycle.LABEL: "abc"}
        c = FakeClient([("c", Res("det", lab, stuck=1)), ("c", Res("sink", lab)), ("n", Res("net", lab)),
                        ("v", Res("vol", lab)), ("c", Res("other", {lifecycle.LABEL: "zzz"}))])
        with mock.patch("time.sleep"):
            r = lifecycle.teardown(c, "abc")
        self.assertTrue(r["destroyed"], r)
        self.assertEqual((r["containers"], r["networks"], r["volumes"]), (2, 1, 1))
        self.assertEqual([x.name for _, x in c.items if not getattr(x, "gone", False)], ["other"])

    def test_teardown_reports_leftovers(self):
        c = FakeClient([("c", Res("stuck", {lifecycle.LABEL: "abc"}, stuck=99))])
        with mock.patch("time.sleep"):
            r = lifecycle.teardown(c, "abc")
        self.assertFalse(r["destroyed"]); self.assertEqual(r["leftover"], ["stuck"])

    def test_reaper_spares_live_scans(self):
        c = FakeClient([("c", Res("live", {lifecycle.LABEL: "L"})), ("c", Res("dead", {lifecycle.LABEL: "D"}))])
        lifecycle.reap(c, live={"L"}, max_age=0)
        self.assertEqual([x.name for _, x in c.items if not getattr(x, "gone", False)], ["live"])


if __name__ == "__main__":
    unittest.main()
