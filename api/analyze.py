"""Stage 6: turn the evidence into a Safe / Suspicious / Malware report.

Rule-based scoring always runs. When VULTR_INFERENCE_API_KEY and AGENT_MODEL are set, the
agent on Vultr Serverless Inference reviews the same evidence (including code that never
executed); it may raise the rule-based verdict but never lower it.
"""
from __future__ import annotations

import json
import os
import re

BENIGN_HOSTS = ("registry.npmjs.org", "github.com", "nodejs.org", "objects.githubusercontent.com")
HOOKS = ("preinstall", "install", "postinstall")
LOADED = "[vulture] loading "
MALWARE_AT, SUSPICIOUS_AT = 60, 25
AI_UNCONFIRMED = "AI assessment, not confirmed by observed behaviour"
SEVERITY = {"safe": 0, "incomplete": 0, "suspicious": 1, "malware": 2}
# Audit #13/#33: say plainly what the sandbox is. Static text: keep in sync with orchestrator.py.
ISOLATION = {
    "technology": "docker (runc) container, shares the host kernel (not a VM / gVisor)",
    "network": "internal docker network without internet; DNS and traffic go to a sinkhole (fake internet)",
    "filesystem": "read-only root, package volume mounted read-only, writable tmpfs /tmp",
    "privileges": "all capabilities dropped, no-new-privileges",
    "limits": "1 GB memory, 2 CPUs, 512 pids, per-step timeout",
    "observation": "strace (execve/open/connect/unlink/rename) + sinkhole log",
}


def coverage(raw: dict) -> dict:
    """Did any package code actually run in the sandbox? (Audit #23/#24/#30)

    deps-rebuild alone does not count: it runs the dependencies' scripts, not the package. A run
    whose package steps all timed out with nothing observed does not count either.
    """
    det = raw.get("detonate") or {}
    runs = det.get("runs") or []
    if det.get("error") or not runs:
        return {"executed": False, "runs": {},
                "reason": f"detonation failed: {det.get('error') or 'no runs were recorded'}"}
    per_run, any_ok = {}, False
    for r in runs:
        o = r.get("observed") or {}
        seen = bool(o.get("honeytoken_access") or o.get("network"))
        ran = []
        for st in r.get("steps") or []:
            out = st.get("output") or ""
            # output keeps only the last 3000 chars; a full buffer may have cut the "loading" lines
            if st.get("label") in HOOKS or (st.get("label") == "entry" and (LOADED in out or len(out) >= 3000)):
                ran.append({"step": st.get("label"), "exit": st.get("exit"),
                            "loaded": [ln[len(LOADED):] for ln in out.splitlines() if ln.startswith(LOADED)][:10]})
        ok = bool(ran) and (seen or any(x["exit"] != "timeout" for x in ran))
        any_ok = any_ok or ok
        per_run[r.get("name", "?")] = {"executed": ok, "steps": ran}
    reason = None
    if not any_ok:
        reason = ("nothing observed: every package step timed out" if any(v["steps"] for v in per_run.values())
                  else "nothing executed: no install scripts and no entry point found")
    return {"executed": any_ok, "runs": per_run, "reason": reason}


def hung_install_steps(raw: dict) -> int:
    """Seconds after which an install hook (preinstall/install/postinstall) was killed, or 0 if none was."""
    secs = [st.get("seconds") or 0 for r in (raw.get("detonate") or {}).get("runs") or []
            for st in r.get("steps") or [] if st.get("label") in HOOKS and st.get("exit") == "timeout"]
    return round(max(secs)) if secs else 0


def evidence(raw: dict) -> dict:
    marker = raw["marker"]
    fetch, det, sink = raw.get("fetch", {}), raw.get("detonate", {}), raw.get("sinkhole", [])
    static = fetch.get("static", {})
    runs = det.get("runs", [])

    honey, procs, net, writes, loaded = [], [], [], set(), set()
    for r in runs:
        o = r.get("observed", {})
        for h in o.get("honeytoken_access", []):
            honey.append({**h, "run": r["name"]})
        for p in o.get("processes", []):
            if p["argv"] and p["argv"][0] not in ("node", "npm", "sh", "/usr/local/bin/node") or len(procs) < 5:
                procs.append({**p, "run": r["name"]})
        net += [{**n, "run": r["name"]} for n in o.get("network", []) if n.get("port") != 53]
        writes.update(o.get("files_written_outside_project", []))
        loaded.update(o.get("code_loaded", []))

    # Confirmed-malicious behaviour inside one process tree (one step of one run): it read a planted
    # secret AND opened an outbound connection (anything but DNS / loopback / unix sockets).
    read_and_connect = []
    for r in runs:
        o = r.get("observed", {})
        read_steps = {h.get("step") for h in o.get("honeytoken_access", []) if h.get("op") == "read"}
        conn_steps = {n.get("step") for n in o.get("network", [])
                      if n.get("ip") and n.get("port") not in (53, None) and not n["ip"].startswith("127.")}
        read_and_connect += [{"run": r["name"], "step": st} for st in sorted(read_steps & conn_steps, key=str)]

    dns = sorted({e["name"] for e in sink if e["kind"] == "dns"} - set(BENIGN_HOSTS))
    requests = [e for e in sink if e["kind"] in ("http", "tls", "tcp")]
    exfil = [e for e in requests if marker in json.dumps(e)]

    # Code paths that never executed: suspicious static findings in files never loaded at runtime.
    dormant = [f for f in static.get("findings", [])
               if f["severity"] in ("high", "medium") and f["file"] not in loaded]
    # Findings in files that did run but whose suspicious branch may not have (e.g. time bombs).
    gated = [f for f in static.get("findings", []) if f["capability"] == "evasion"]

    by_run = {r["name"]: {"honeytoken_hits": len(r.get("observed", {}).get("honeytoken_access", [])),
                          "network": len(r.get("observed", {}).get("network", [])),
                          "processes": len(r.get("observed", {}).get("processes", []))} for r in runs}
    return {
        "target": fetch.get("meta", {}),
        "install_scripts": static.get("install_scripts", []),
        "static_summary": static.get("summary", {}),
        "static_findings": static.get("findings", [])[:60],
        "honeytoken_access": honey[:50],
        "exfiltration": exfil[:20],
        "dns_lookups": dns[:50],
        "requests": requests[:40],
        "connections": net[:40],
        "processes": procs[:40],
        "files_written_outside_project": sorted(writes)[:40],
        "dormant_code": dormant[:30],
        "trigger_conditions": gated[:20],
        "matrix": by_run,
        "read_and_connect": read_and_connect[:20],
    }


def score(ev: dict) -> dict:
    reasons, s = [], 0
    if ev["exfiltration"]:
        s += 60; reasons.append(f"sent planted secrets to {len(ev['exfiltration'])} remote endpoint(s)")
    reads = [h for h in ev["honeytoken_access"] if h["op"] == "read"]
    if reads:
        s += 30; reasons.append(f"read {len({h['file'] for h in reads})} planted credential file(s)")
    if ev["dns_lookups"]:
        s += 15; reasons.append(f"contacted unexpected hosts: {', '.join(ev['dns_lookups'][:4])}")
    shells = [p for p in ev["processes"] if p["argv"] and any(x in " ".join(p["argv"]) for x in ("curl", "wget", "bash -c", "sh -c", "powershell", "nc "))]
    if shells:
        s += 15; reasons.append("spawned shell / download commands")
    sm = ev["static_summary"]
    if sm.get("high"):
        s += min(5 * sm["high"], 20); reasons.append(f"{sm['high']} high-severity static findings")
    if any(i["is_root"] for i in ev["install_scripts"]):
        s += 5; reasons.append("runs code at install time")
    if ev["trigger_conditions"]:
        s += 10; reasons.append("code checks time / CI / environment before acting (possible evasion)")
    # MALWARE only on observed behaviour: the scan marker reached the fake internet, or one process tree
    # read a planted secret and connected out. A high score without that stays SUSPICIOUS.
    confirmed = []
    if ev["exfiltration"]:
        confirmed.append("planted secret marker reached the fake internet")
    if ev.get("read_and_connect"):
        x = ev["read_and_connect"][0]
        confirmed.append(f"read a planted secret and connected out in one process tree ({x['run']} / {x['step']})")
    if confirmed:
        verdict = "malware"
        reasons.insert(0, "confirmed by observed behaviour: " + "; ".join(confirmed))
    else:
        verdict = "suspicious" if s >= SUSPICIOUS_AT else "safe"
        if s >= MALWARE_AT:
            reasons.append("high risk score, but no exfiltration or secret-read + connection was observed")
    return {"verdict": verdict, "risk_score": min(s, 100), "reasons": reasons, "confirmed": confirmed}


PROMPT = """You are Vulture, a malware analyst for open-source packages. You get evidence from a
static scan and from detonating the package in a sandbox with planted honeytokens (fake credentials
containing a marker, shown to you as <HONEYTOKEN>), a fake internet (sinkhole), several personas and a clock pushed forward.

Also reason about DORMANT code: suspicious code that never executed, and what condition would trigger it
(dates, CI variables, OS, hostnames, arguments).

Reply with ONE JSON object only:
{"verdict": "safe" | "suspicious" | "malware", "confidence": 0-1, "summary": "2-4 sentences for a developer",
 "indicators": [{"title": "...", "severity": "low|medium|high", "evidence": "..."}],
 "dormant_triggers": [{"file": "...", "condition": "...", "would_do": "..."}],
 "recommendation": "..."}"""


_S = {"type": "string"}
AI_RESPONSE_FORMAT = {"type": "json_schema", "json_schema": {"name": "vulture_verdict", "strict": True, "schema": {
    "type": "object", "additionalProperties": False,
    "required": ["verdict", "confidence", "summary", "indicators", "dormant_triggers", "recommendation"],
    "properties": {
        "verdict": {"type": "string", "enum": ["safe", "suspicious", "malware"]},
        "confidence": {"type": "number"},
        "summary": _S,
        "indicators": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["title", "severity", "evidence"],
            "properties": {"title": _S, "severity": {"type": "string", "enum": ["low", "medium", "high"]},
                           "evidence": _S}}},
        "dormant_triggers": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["file", "condition", "would_do"],
            "properties": {"file": _S, "condition": _S, "would_do": _S}}},
        "recommendation": _S}}}}


def _str(x) -> bool:
    return isinstance(x, str) and bool(x.strip())


def validate_ai(obj) -> dict:
    """Manual schema check of the model reply (Audit #28). Raises ValueError if unusable;
    malformed list items are dropped, optional fields are normalised."""
    if not isinstance(obj, dict):
        raise ValueError("reply is not a JSON object")
    if obj.get("verdict") not in ("safe", "suspicious", "malware"):
        raise ValueError(f"bad verdict {str(obj.get('verdict'))[:40]!r}")
    if not _str(obj.get("summary")):
        raise ValueError("missing summary")
    c = obj.get("confidence")
    conf = float(c) if isinstance(c, (int, float)) and not isinstance(c, bool) and 0 <= c <= 1 else None
    ind = [{k: i[k] for k in ("title", "severity", "evidence")} for i in obj.get("indicators") or []
           if isinstance(i, dict) and _str(i.get("title")) and i.get("severity") in ("low", "medium", "high")
           and isinstance(i.get("evidence"), str)] if isinstance(obj.get("indicators"), list) else []
    dor = [{k: d[k] for k in ("file", "condition", "would_do")} for d in obj.get("dormant_triggers") or []
           if isinstance(d, dict) and all(isinstance(d.get(k), str) for k in ("file", "condition", "would_do"))] \
        if isinstance(obj.get("dormant_triggers"), list) else []
    rec = obj.get("recommendation") if isinstance(obj.get("recommendation"), str) else ""
    return {"verdict": obj["verdict"], "confidence": conf, "summary": obj["summary"], "indicators": ind,
            "dormant_triggers": dor, "recommendation": rec}


def llm_report(ev: dict, rules: dict, marker: str = "") -> dict | None:
    key, model = os.environ.get("VULTR_INFERENCE_API_KEY"), os.environ.get("AGENT_MODEL")
    if not key or not model:
        return None
    from openai import OpenAI
    # 2 attempts x 60 s, no hidden SDK retries: a dead model costs ~2 min, not 6+ (Audit #28)
    client = OpenAI(base_url=os.environ.get("VULTR_INFERENCE_BASE_URL", "https://api.vultrinference.com/v1"),
                    api_key=key, timeout=60, max_retries=0)
    content = json.dumps({"rule_based": rules, "evidence": ev})
    if marker:
        content = content.replace(marker, "<HONEYTOKEN>")   # Audit #27: never send the scan marker out
    content = content[:60000]
    last, diag = "no reply", {}
    # Reasoning tokens count against max_tokens: with 1500 and default effort the model often spent
    # all of them thinking and returned empty content (finish_reason=length). Low effort + 4000 tokens,
    # and a JSON schema so the reply is a bare object. One retry, and only when validation fails.
    for _ in range(2):
        try:
            r = client.chat.completions.create(model=model, temperature=0.1, max_tokens=4000,
                                               reasoning_effort="low", response_format=AI_RESPONSE_FORMAT,
                                               messages=[{"role": "system", "content": PROMPT},
                                                         {"role": "user", "content": content}])
        except Exception as e:
            return {"error": f"model failed: {e}"[:500]} | diag
        raw_text = r.choices[0].message.content or ""
        diag = _diag(r, raw_text, marker)
        text = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.S)
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            last = "model reply failed validation: no JSON object in reply"
            continue
        try:
            return validate_ai(json.loads(m.group(0))) | diag
        except ValueError as e:   # json.JSONDecodeError is a ValueError too
            last = f"model reply failed validation: {e}"
    return {"error": str(last)[:500]} | diag


def _diag(r, raw_text: str, marker: str) -> dict:
    """What the model actually sent back (first 2000 chars, marker masked), to debug bad replies."""
    excerpt = raw_text[:2000]
    if marker:
        excerpt = excerpt.replace(marker, "<HONEYTOKEN>")
    u = getattr(r, "usage", None)
    details = getattr(u, "completion_tokens_details", None) if u else None
    return {"raw_excerpt": excerpt, "raw_length": len(raw_text),
            "finish_reason": getattr(r.choices[0], "finish_reason", None),
            "completion_tokens": getattr(u, "completion_tokens", None) if u else None,
            "reasoning_tokens": getattr(details, "reasoning_tokens", None) if details else None}


def report(raw: dict) -> dict:
    ev = evidence(raw)
    rules = score(ev)
    rules["coverage"] = cov = coverage(raw)
    if not cov["executed"]:
        rules["reasons"].insert(0, cov["reason"])
        # Only "safe" is replaced: it would claim we watched the package run and saw nothing.
        # Evidence that already reached suspicious/malware (static or behavioural) stays as is.
        if rules["verdict"] == "safe":
            rules["verdict"] = "incomplete"
    hung = hung_install_steps(raw)
    if hung:
        rules["reasons"].insert(0, f"install script did not finish within {hung} s")
        observed = (ev["honeytoken_access"] or ev["exfiltration"] or ev["dns_lookups"] or ev["requests"]
                    or ev["connections"] or ev["files_written_outside_project"])
        if SEVERITY[rules["verdict"]] < SEVERITY["suspicious"]:
            # A hung install script with nothing else seen means we never saw what it would do.
            rules["verdict"] = "suspicious" if observed else "incomplete"
    ai = llm_report(ev, rules, raw.get("marker", ""))
    # Rules are the floor (Audit #25): the model may raise the verdict, never lower it, and only up to
    # SUSPICIOUS. MALWARE is set by the rules alone, from observed behaviour. "incomplete" ranks with
    # "safe", so the model can raise it but can never turn it into "safe".
    final, source = rules["verdict"], "rules"
    if ai and ai.get("verdict") == "malware" and rules["verdict"] != "malware":
        ai["note"] = AI_UNCONFIRMED
    if ai and min(SEVERITY.get(ai.get("verdict"), -1), SEVERITY["suspicious"]) > SEVERITY[final]:
        final, source = "suspicious", "ai"
    return {"verdict": final, "verdict_source": source, "rules": rules, "ai": ai, "evidence": ev,
            "isolation": dict(ISOLATION)}
