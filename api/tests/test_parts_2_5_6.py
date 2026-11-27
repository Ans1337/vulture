"""Storage / cancel / dedupe (Part 2), Vultr VM lifecycle (Part 5), investigator loop (Part 6). No Docker, no network."""
import asyncio, json, os, sys, tempfile, threading, time, types, unittest
from unittest import mock

os.environ.update(VULTURE_DB=os.path.join(tempfile.mkdtemp(), "p.db"), APP_TOKEN="t" * 32, RATE_API_PER_MIN="10000",
                  RATE_SCANS_PER_HOUR="10000")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from fastapi.testclient import TestClient
import app as appmod, store, vultr, investigator, analyze, orchestrator, security

H = {"Authorization": "Bearer " + "t" * 32, "X-Vulture-Nonce": "n" * 40}


def reset_db():
    if os.path.exists(store.DB_PATH):
        os.remove(store.DB_PATH)
    return store.init()


def wait(pred, t=3):
    end = time.time() + t
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


class StorageTest(unittest.TestCase):
    def setUp(self):
        reset_db(); security.LIMITER.hits.clear()
        self.c = TestClient(appmod.app, raise_server_exceptions=False)

    def test_source_key_only_for_pinned_sources(self):
        self.assertEqual(store.source_key("left-pad@1.3.0"), "npm:left-pad@1.3.0")
        self.assertEqual(store.source_key("npm:@a/b@2.0.0-rc.1"), "npm:@a/b@2.0.0-rc.1")
        self.assertIsNone(store.source_key("left-pad"))
        self.assertIsNone(store.source_key("https://github.com/a/b#main"))
        self.assertTrue(store.source_key("https://github.com/A/b#" + "a" * 40).endswith("#" + "a" * 40))

    def test_restart_marks_interrupted_scans_failed_and_keeps_history(self):
        store.create("a1", "left-pad", "docker"); store.set_status("a1", "running")
        store.create("a2", "x", "docker"); store.set_status("a2", "done", verdict="safe", finished=1.0)
        self.assertEqual(store.init(), 1)
        self.assertEqual(store.get("a1")["status"], "failed")
        self.assertIn("restart", store.get("a1")["error"])
        self.assertEqual(store.get("a2")["verdict"], "safe")          # history survives

    def test_finished_scans_stay_finished(self):
        store.create("b1", "x", "docker"); store.set_status("b1", "cancelled", error="c")
        store.set_status("b1", "running")
        self.assertEqual(store.get("b1")["status"], "cancelled")

    def test_events_after_cursor_and_prune(self):
        store.create("c1", "x", "docker")
        for i in range(3): store.add_event("c1", i, "fetch", f"m{i}", {})
        first = store.get("c1")["events"]
        self.assertEqual(len(store.get("c1", after_event=first[1]["id"])["events"]), 1)
        for i in range(5):
            store.create(f"d{i}", "x", "docker"); store.set_status(f"d{i}", "done", finished=1.0)
        store.prune(2)
        self.assertEqual(len(store.list_scans()), 3)                    # 2 finished + the queued one
        self.assertIsNone(store.get_evidence("d0"))

    def test_search_filters_and_like_escaping(self):
        store.create("e1", "left-pad", "docker"); store.create("e2", "100%_sure", "docker")
        self.assertEqual([s["id"] for s in store.list_scans(q="left")], ["e1"])
        self.assertEqual([s["id"] for s in store.list_scans(q="%")], ["e2"])

    def test_scan_end_to_end_dedupe_reanalyze_evidence(self):
        raw = {"marker": "M", "fetch": {"meta": {"name": "left-pad"}, "static": {}}, "detonate": {"runs": []}, "sinkhole": []}
        with mock.patch.object(appmod.orchestrator, "run_scan", return_value=raw):
            sid = self.c.post("/api/scans", data={"source": "left-pad@1.3.0"}, headers=H).json()["id"]
            self.assertTrue(wait(lambda: store.status_of(sid) == "done"))
            r = self.c.post("/api/scans", data={"source": "left-pad@1.3.0"}, headers=H)   # already scanned
            self.assertEqual((r.status_code, r.json()), (200, {"id": sid, "deduped": True}))
            r = self.c.post("/api/scans", data={"source": "left-pad@1.3.0", "force": "true"}, headers=H)
            self.assertEqual(r.status_code, 201); self.assertNotEqual(r.json()["id"], sid)
        self.assertEqual(self.c.get(f"/api/scans/{sid}/evidence", headers=H).json()["marker"], "M")
        self.assertEqual(self.c.post(f"/api/scans/{sid}/reanalyze", headers=H).json()["verdict"], "incomplete")
        got = self.c.get(f"/api/scans/{sid}", headers=H).json()
        self.assertEqual((got["status"], got["verdict"]), ("done", "incomplete"))
        self.assertEqual(self.c.get("/api/scans?verdict=incomplete", headers=H).json()[0]["id"], sid)

    def test_cancel_running_scan(self):
        started = threading.Event()

        def slow(scan_id, source, upload, emit, cancel=None, mode="docker"):
            started.set()
            cancel.wait(5)
            raise orchestrator.Cancelled()
        with mock.patch.object(appmod.orchestrator, "run_scan", side_effect=slow):
            sid = self.c.post("/api/scans", data={"source": "x"}, headers=H).json()["id"]
            self.assertTrue(started.wait(3))
            self.assertEqual(self.c.post(f"/api/scans/{sid}/cancel", headers=H).status_code, 200)
            self.assertTrue(wait(lambda: store.status_of(sid) == "cancelled"))
        self.assertEqual(self.c.post(f"/api/scans/{sid}/cancel", headers=H).status_code, 409)
        self.assertEqual(self.c.post("/api/scans/nope/cancel", headers=H).status_code, 404)


class FakeVultr:
    """In-memory stand-in for the Vultr REST API."""
    def __init__(self, boots_after=1, delete_fails=0):
        self.vms, self.polls, self.boots_after, self.delete_fails, self.calls = {}, 0, boots_after, delete_fails, []

    def __call__(self, method, path, body):
        self.calls.append((method, path))
        if method == "POST" and path == "/instances":
            self.vms["vm1"] = {"id": "vm1-aaaaaaaa", "status": "pending", "main_ip": "0.0.0.0", "tags": body["tags"],
                               "date_created": "2020-01-01T00:00:00+00:00", "body": body}
            return 202, {"instance": self.vms["vm1"]}
        if method == "GET" and path.startswith("/instances?"):
            return 200, {"instances": list(self.vms.values()), "meta": {"links": {}}}
        vm = next((v for v in self.vms.values() if path.endswith(v["id"])), None)
        if method == "GET":
            if not vm: return 404, {}
            self.polls += 1
            if self.polls >= self.boots_after:
                vm.update(status="active", main_ip="203.0.113.7")
            return 200, {"instance": vm}
        if method == "DELETE":
            if self.delete_fails > 0:
                self.delete_fails -= 1; return 500, {}
            if vm: del self.vms["vm1"]
            return 204, {}
        return 400, {}


class VultrTest(unittest.TestCase):
    def sandbox(self, fake, ssh_ok=True, cancel=None):
        self.events = []
        return vultr.Sandbox("abc123", lambda *a: self.events.append(a), cancel=cancel, api=vultr.Vultr("k", fake),
                             ssh=lambda ip, cmd, timeout=15: types.SimpleNamespace(returncode=0 if ssh_ok else 1),
                             sleep=lambda s: None)

    def test_vm_created_booted_and_destroyed(self):
        fake = FakeVultr(boots_after=3)
        fake_docker = types.SimpleNamespace(DockerClient=mock.Mock(return_value="client"))
        with mock.patch.dict(sys.modules, {"docker": fake_docker}):
            with self.sandbox(fake) as client:
                self.assertEqual(client, "client")
                fake_docker.DockerClient.assert_called_once()
                self.assertIn("203.0.113.7", fake_docker.DockerClient.call_args.kwargs["base_url"])
                self.assertEqual(len(fake.vms), 1)
        self.assertEqual(fake.vms, {})
        states = [e[2].get("vm") for e in self.events if e[2].get("vm")]
        self.assertEqual(states, ["creating", "created", "ready", "destroyed"])

    def test_vm_destroyed_even_when_the_scan_body_raises(self):
        fake = FakeVultr()
        with mock.patch.dict(sys.modules, {"docker": types.SimpleNamespace(DockerClient=mock.Mock())}):
            with self.assertRaises(ValueError), self.sandbox(fake):
                raise ValueError("scan blew up")
        self.assertEqual(fake.vms, {})

    def test_boot_timeout_destroys_vm(self):
        fake = FakeVultr(boots_after=10**9)
        sb = self.sandbox(fake)
        with mock.patch.dict(os.environ, {"VULTR_BOOT_TIMEOUT": "0"}), self.assertRaises(TimeoutError):
            sb.__enter__()
        self.assertEqual(fake.vms, {})

    def test_cancel_during_boot_destroys_vm(self):
        fake, cancel = FakeVultr(boots_after=10**9), threading.Event(); cancel.set()
        with self.assertRaises(InterruptedError):
            self.sandbox(fake, cancel=cancel).__enter__()
        self.assertEqual(fake.vms, {})

    def test_delete_is_retried_and_failure_is_reported(self):
        fake = FakeVultr(delete_fails=2)
        with mock.patch.dict(sys.modules, {"docker": types.SimpleNamespace(DockerClient=mock.Mock())}):
            with self.sandbox(fake): pass
        self.assertEqual(fake.vms, {})
        fake = FakeVultr(delete_fails=99)
        with mock.patch.dict(sys.modules, {"docker": types.SimpleNamespace(DockerClient=mock.Mock())}):
            with self.sandbox(fake): pass
        self.assertFalse(self.events[-1][2]["vm_report"]["destroyed"])

    def test_create_request_is_tagged_and_uses_snapshot_when_set(self):
        fake = FakeVultr()
        with mock.patch.dict(os.environ, {"VULTR_SNAPSHOT_ID": "snap-1", "VULTR_FIREWALL_GROUP_ID": "fw-1"}):
            vultr.Vultr("k", fake).create_instance("abc", "#!/bin/bash")
        body = fake.vms["vm1"]["body"]
        self.assertEqual((body["snapshot_id"], body["firewall_group_id"]), ("snap-1", "fw-1"))
        self.assertIn("vulture-scan", body["tags"]); self.assertNotIn("os_id", body)

    def test_janitor_spares_live_and_young_vms(self):
        fake = FakeVultr(); api = vultr.Vultr("k", fake)
        api.create_instance("dead", "x"); self.assertEqual(vultr.janitor(api, {"live"}, 60), 1)
        api.create_instance("live", "x"); self.assertEqual(vultr.janitor(api, {"live"}, 60), 0)
        api.create_instance("young", "x"); fake.vms["vm1"]["date_created"] = "2999-01-01T00:00:00+00:00"
        self.assertEqual(vultr.janitor(api, set(), 60), 0)

    def test_needs_api_key(self):
        with mock.patch.dict(os.environ, {"VULTR_API_KEY": ""}), self.assertRaises(vultr.VultrError):
            vultr.Vultr()


class Msg:
    def __init__(self, content="", calls=()):
        self.content = content
        self.tool_calls = [types.SimpleNamespace(id=f"c{i}", function=types.SimpleNamespace(name=n, arguments=json.dumps(a)))
                           for i, (n, a) in enumerate(calls)] or None


class FakeLLM:
    def __init__(self, script): self.script, self.seen = list(script), []
    async def create(self, **kw):
        self.seen.append(kw["messages"][-1])
        x = self.script.pop(0)
        if callable(x): x = await x()
        if isinstance(x, Exception): raise x
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=x)])


class Ctx:
    def __init__(self): self.log = []
    def cancelled(self): return False
    def remaining(self, n): return n
    def inspect(self, cmd, arg): self.log.append((cmd, arg)); return f"{cmd}:{arg}-output"
    def rerun(self, persona, clock): self.log.append(("rerun", persona, clock)); return {"persona": persona, "exfiltration": [1]}


RAW = {"marker": "M", "fetch": {"meta": {}, "static": {}}, "detonate": {"runs": []}, "sinkhole": []}


class InvestigatorTest(unittest.TestCase):
    def run_loop(self, script, ctx=None, raw=RAW):
        llm = FakeLLM(script); events = []
        client = mock.MagicMock(chat=types.SimpleNamespace(completions=llm))
        with mock.patch.object(investigator, "_client", return_value=(client, "m")):
            out = investigator.investigate(ctx or Ctx(), raw, lambda s, m, d: events.append((s, m, d)))
        return out, events, llm

    def test_agent_inspects_reruns_and_concludes(self):
        ctx = Ctx()
        out, events, llm = self.run_loop([
            Msg("check the gate", [("grep", {"pattern": "Date"})]),
            Msg("", [("rerun", {"persona": "ci", "clock": "+90d"})]),
            Msg('{"findings": ["steals on ci"], "leaning": "malware", "unexplained": []}')], ctx)
        self.assertEqual([x[0] for x in ctx.log], ["grep", "rerun"])
        self.assertEqual(out["conclusion"]["leaning"], "malware")
        self.assertEqual((out["steps_used"], out["reruns"]), (2, 1))
        self.assertEqual(out["stop_reason"], "concluded")
        self.assertIn("exfiltration", llm.seen[-1]["content"])
        self.assertTrue(any("rerun(persona=ci" in e[1] for e in events))        # streamed to the UI

    def test_rerun_args_validated_and_budgeted(self):
        ctx = Ctx(); calls = [("rerun", {"persona": "root", "clock": "0"}), ("rerun", {"persona": "ci", "clock": "tomorrow"})]
        calls += [("rerun", {"persona": "ci", "clock": f"+{i}d"}) for i in range(1, 6)]
        out, *_ = self.run_loop([Msg("", calls), Msg('{"leaning": "safe", "unexplained": []}')], ctx)
        self.assertEqual(len([x for x in ctx.log if x[0] == "rerun"]), investigator.MAX_RERUNS)
        self.assertIn("invalid", out["steps"][0]["result"])
        self.assertEqual(out["stop_reason"], "rerun_limit")
        self.assertIn("clock=+4d", out["unanswered"][0])

    def test_baseline_can_be_enough_without_any_followup(self):
        out, _, llm = self.run_loop([Msg('{"leaning":"safe","unexplained":[]}')])
        self.assertEqual((out["stop_reason"], out["reruns"], len(llm.seen)), ("concluded", 0, 1))

    def test_final_turn_cannot_run_another_tool(self):
        ctx = Ctx()
        call = Msg("", [("rerun", {"persona": "ci", "clock": "0"})])
        out, _, llm = self.run_loop([call] * 4, ctx)
        self.assertEqual((out["stop_reason"], len(ctx.log), len(llm.seen)), ("rerun_limit", 3, 4))
        self.assertIsNone(out["conclusion"])

    def test_inflight_inference_is_cancelled_at_deadline(self):
        sink = mock.Mock()
        sink.logs.return_value = b""
        ctx = orchestrator.Investigation(None, None, None, sink, None, RAW, {}, lambda cap: cap, None)
        cancelled = []
        async def stalled():
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.append(True)
        ctx.deadline = time.monotonic() + 0.1
        out, _, llm = self.run_loop([stalled], ctx)
        self.assertEqual((out["stop_reason"], len(llm.seen), out["reruns"]), ("timeout", 1, 0))
        self.assertEqual(cancelled, [True])

    def test_deadline_between_batched_tools_preserves_the_first_result(self):
        ctx = Ctx()
        def remaining(cap):
            if ctx.log:
                raise TimeoutError
            return cap
        ctx.remaining = remaining
        calls = [("rerun", {"persona": "ci", "clock": clock}) for clock in ("0", "+7d")]
        out, *_ = self.run_loop([Msg("", calls)], ctx)
        self.assertEqual((out["stop_reason"], out["reruns"], len(out["steps"])), ("timeout", 1, 1))
        self.assertIn("+7d", out["unanswered"][0])

    def test_followup_observations_and_model_questions_reach_the_verdict(self):
        run = {"name": "ci", "steps": [{"label": "entry", "exit": 0, "output": "[vulture] loading index.js"}]}
        raw = {**RAW, "investigation": {"conclusion": {"unexplained": ["Which config is missing?"]}},
               "followups": [{"persona": "ci", "clock": "0", "detonate": {"runs": [run]},
                              "sinkhole": [{"kind": "http", "body": RAW["marker"]}]}]}
        with mock.patch.object(analyze, "llm_report", return_value=None):
            rep = analyze.report(raw)
        self.assertEqual(rep["verdict"], "malware")
        self.assertTrue(rep["rules"]["coverage"]["executed"])
        self.assertIn("ci (follow-up 1)", rep["evidence"]["matrix"])
        self.assertEqual(rep["rules"]["unresolved"], ["Which config is missing?"])

    def test_timeout_without_conclusion_identifies_unverified_findings(self):
        finding = {"file": "index.js", "line": 4, "capability": "evasion", "severity": "medium", "rule": "ci_check"}
        raw = {**RAW, "investigation": {"stop_reason": "timeout"}, "fetch": {"static": {"findings": [finding]}}}
        with mock.patch.object(analyze, "llm_report", return_value=None):
            gaps = analyze.report(raw)["rules"]["unresolved"]
        self.assertEqual(sum("index.js:4 (ci_check)" in item for item in gaps), 1)

    def test_model_failures_retry_then_stop(self):
        out, events, _ = self.run_loop([RuntimeError("x")] * 3)
        self.assertEqual(out["steps"], []); self.assertEqual(sum("retrying" in e[1] for e in events), 2)
        self.assertEqual(out["stop_reason"], "model_error")

    def test_bad_final_json_asks_again(self):
        out, *_ = self.run_loop([Msg("no json here"), Msg('{"leaning": "safe", "unexplained": []}')])
        self.assertEqual(out["conclusion"], {"leaning": "safe", "unexplained": []})

    def test_step_budget_is_enforced(self):
        script = [Msg("", [("list_files", {})]) for _ in range(investigator.MAX_STEPS)]
        out, events, _ = self.run_loop(script + [Msg('{"leaning": "safe", "unexplained": []}')])
        self.assertEqual(out["steps_used"], investigator.MAX_STEPS)
        self.assertTrue(any("budget" in e[1] for e in events))

    def test_tool_errors_go_back_to_the_model(self):
        ctx = Ctx(); ctx.inspect = mock.Mock(side_effect=OSError("disk"))
        out, *_ = self.run_loop([Msg("", [("read_file", {"path": "a"})]), Msg('{"leaning": "safe", "unexplained": []}')], ctx)
        self.assertIn("tool error", out["steps"][0]["result"])

    def test_skipped_without_inference_key(self):
        events = []
        with mock.patch.object(investigator, "_client", return_value=(None, None)):
            out = investigator.investigate(Ctx(), RAW, lambda *a: events.append(a))
        self.assertTrue(out["skipped"])

    def test_marker_is_masked_before_it_reaches_the_model(self):
        class C(Ctx):
            def inspect(self, cmd, arg): return "found MARK in file"
        raw = {**RAW, "marker": "MARK"}
        llm = FakeLLM([Msg("", [("read_file", {"path": "a"})]), Msg('{"leaning": "safe", "unexplained": []}')])
        client = mock.MagicMock(chat=types.SimpleNamespace(completions=llm))
        with mock.patch.object(investigator, "_client", return_value=(client, "m")):
            out = investigator.investigate(C(), raw, lambda *a: None)
        self.assertNotIn("MARK", json.dumps(llm.seen)); self.assertNotIn("MARK", out["steps"][0]["result"])
        self.assertIn("<HONEYTOKEN>", out["steps"][0]["result"])

    def test_investigation_trace_reaches_the_report_but_cannot_lower_the_verdict(self):
        raw = {**RAW, "marker": "MARK", "investigation": {"steps": [], "conclusion": {"leaning": "safe"}},
               "sinkhole": [{"kind": "http", "host": "evil.example", "body": "MARK stolen"}]}
        self.assertIn("investigation", analyze.evidence(raw))
        with mock.patch.object(analyze, "llm_report", return_value={"verdict": "safe", "summary": "trust me"}):
            self.assertEqual(analyze.report(raw)["verdict"], "malware")        # rules are the floor


if __name__ == "__main__":
    unittest.main()
