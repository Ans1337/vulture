"""Stage 3 (network = sinkhole only): run the package across the persona x clock matrix
under strace, with honeytokens planted, and report everything it touched.

Env: MARKER (unique honeytoken marker), PERSONAS (comma list), CLOCKS (comma list,
e.g. "0,+30d,+90d"), STEP_TIMEOUT (seconds per command).
"""
import json, os, re, shutil, signal, subprocess, time
from pathlib import Path
from common import progress, result

PKG = Path("/work/pkg")
RUNS = Path("/tmp/runs")
MARKER = os.environ.get("MARKER", "VULTUREHONEY")
STEP_TIMEOUT = int(os.environ.get("STEP_TIMEOUT", "60"))
FAKETIME_LIB = "/usr/local/lib/libfaketime.so.1"
LIFECYCLE = ("preinstall", "install", "postinstall")

PERSONAS = {
    "developer": {
        "user": "alice", "host": "alice-mbp",
        "env": {"USER": "alice", "LOGNAME": "alice", "TERM": "xterm-256color", "LANG": "en_US.UTF-8",
                "EDITOR": "vim", "SHELL": "/bin/zsh"},
    },
    "ci": {
        "user": "runner", "host": "fv-az123-456",
        "env": {"USER": "runner", "CI": "true", "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/payments",
                "GITHUB_WORKFLOW": "release", "RUNNER_OS": "Linux", "GITHUB_TOKEN": f"ghs_{MARKER}CI000000000000000000",
                "NPM_TOKEN": f"npm_{MARKER}CI0000000000000000000"},
    },
    "server": {
        "user": "deploy", "host": "prod-api-01",
        "env": {"USER": "deploy", "NODE_ENV": "production", "DATABASE_URL": f"postgres://app:{MARKER}db@10.0.0.5/prod"},
    },
}


def honeytokens(home: Path, project: Path, persona: str):
    """Plant fake secrets. Each carries MARKER so exfiltration shows up in sinkhole logs."""
    t = {
        home / ".aws/credentials": f"[default]\naws_access_key_id = AKIA{MARKER[:12].upper():0<16}\n"
                                   f"aws_secret_access_key = {MARKER}aws/secret/key0000000000000\n",
        home / ".npmrc": f"//registry.npmjs.org/:_authToken=npm_{MARKER}000000000000000000000\n",
        home / ".ssh/id_rsa": f"-----BEGIN OPENSSH PRIVATE KEY-----\n{MARKER}b3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
        home / ".gitconfig": "[user]\n\tname = Alice Dev\n\temail = alice@example.com\n",
        home / ".git-credentials": f"https://alice:ghp_{MARKER}0000000000000000@github.com\n",
        home / ".config/solana/id.json": json.dumps([ord(c) % 256 for c in (MARKER * 8)[:64]]),
        home / ".ethereum/keystore/UTC--wallet.json": json.dumps({"address": "0x" + "ab" * 20, "crypto": {"ciphertext": MARKER}}),
        home / ".docker/config.json": json.dumps({"auths": {"ghcr.io": {"auth": MARKER}}}),
        home / ".kube/config": f"apiVersion: v1\nusers:\n- name: prod\n  user:\n    token: {MARKER}kube\n",
        home / ".bash_history": "ssh deploy@prod-api-01\naws s3 ls\n",
        project / ".env": f"STRIPE_SECRET_KEY=sk_live_{MARKER}000000\nOPENAI_API_KEY=sk-{MARKER}0000\n",
    }
    for p, content in t.items():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    (home / ".ssh").chmod(0o700)
    return [str(p) for p in t]


ENTRY_JS = r"""
const path = require('path'); const fs = require('fs');
const root = process.cwd(); let pj = {};
try { pj = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')); } catch (e) {}
const targets = new Set();
if (pj.main) targets.add(pj.main); if (typeof pj.exports === 'string') targets.add(pj.exports);
if (pj.exports && pj.exports['.']) { const e = pj.exports['.']; targets.add(typeof e === 'string' ? e : (e.require || e.import || e.default)); }
if (pj.bin) for (const b of (typeof pj.bin === 'string' ? [pj.bin] : Object.values(pj.bin))) targets.add(b);
if (!targets.size) targets.add('index.js');
(async () => {
  for (const t of targets) {
    if (!t || typeof t !== 'string') continue;
    const f = path.resolve(root, t);
    if (!fs.existsSync(f)) continue;
    console.log('[vulture] loading ' + t);
    try { require(f); } catch (e) {
      if (e.code === 'ERR_REQUIRE_ESM') { try { await import('file://' + f); } catch (e2) { console.log('[vulture] import error ' + e2.message); } }
      else console.log('[vulture] require error ' + e.message);
    }
  }
  setTimeout(() => process.exit(0), 8000);  // let timers and delayed callbacks fire
})();
"""

TRACE_RX = re.compile(r'^(?P<pid>\d+)\s+(?P<call>\w+)\((?P<args>.*)\)\s+=\s+(?P<ret>-?\d+|\?)(?P<rest>.*)$')


def parse_trace(path: Path, home: Path, project: Path, tokens: list[str]):
    procs, reads, writes, net, deleted, honey = [], set(), set(), [], set(), []
    token_set = set(tokens)
    if not path.exists():
        return {}
    for line in path.read_text(errors="replace").splitlines():
        m = TRACE_RX.match(line)
        if not m:
            continue
        call, args, ret = m["call"], m["args"], m["ret"]
        ok = ret != "?" and not ret.startswith("-")
        if call == "execve":
            argv = re.findall(r'"((?:[^"\\]|\\.)*)"', args.split("], ")[0])
            if argv:
                procs.append({"argv": argv[1:8] if len(argv) > 1 else argv, "ok": ok})
        elif call in ("openat", "open"):
            fm = re.search(r'"([^"]+)"', args)
            if not fm:
                continue
            f = fm.group(1)
            if f.startswith(("/proc", "/sys", "/dev", "/etc/ld.so", "/lib", "/usr/lib", "/usr/local/lib/node_modules/npm")):
                continue
            is_write = any(x in args for x in ("O_WRONLY", "O_RDWR", "O_CREAT"))
            (writes if is_write else reads).add(f)
            if f in token_set or any(f.startswith(t) for t in token_set):
                honey.append({"file": f, "op": "write" if is_write else "read", "ok": ok})
        elif call in ("connect", "sendto"):
            ip = re.search(r'inet_(?:addr|pton)\((?:AF_INET6?, )?"([^"]+)"\)', args)
            port = re.search(r'sin6?_port=htons\((\d+)\)', args)
            if ip:
                net.append({"call": call, "ip": ip.group(1), "port": int(port.group(1)) if port else None, "ok": ok})
            elif "sun_path" in args:
                sp = re.search(r'sun_path="([^"]+)"', args)
                if sp and "nscd" not in sp.group(1):
                    net.append({"call": call, "unix": sp.group(1), "ok": ok})
        elif call in ("unlink", "unlinkat", "rename", "renameat", "renameat2"):
            fm = re.findall(r'"([^"]+)"', args)
            deleted.update(fm)

    sensitive_etc = ("/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname", "/etc/resolv.conf")

    def outside(paths):
        keep = []
        for p in paths:
            if p.startswith(str(project)) or "/npm-cache" in p or p.startswith(("/usr/local/", "/usr/share/", "/tmp/runs/") ) and not p.startswith(str(home)):
                continue
            if p.startswith("/etc/") and p not in sensitive_etc:
                continue
            keep.append(p)
        return sorted(keep)

    js_loaded = sorted({p.removeprefix(str(project) + "/") for p in reads if p.startswith(str(project))
                        and p.endswith((".js", ".cjs", ".mjs", ".node", ".sh", ".py"))})
    return {
        "processes": procs[:200],
        "honeytoken_access": honey,
        "files_read_outside_project": [p for p in outside(reads) if p not in token_set][:200],
        "files_written_outside_project": outside(writes)[:200],
        "files_deleted_or_renamed": sorted(deleted)[:100],
        "network": net[:200],
        "code_loaded": js_loaded[:500],
    }


def _kill_leftovers(pgid):
    """Kill the step's process group, then anything else still alive in the container
    (a child that called setsid() escapes the group). Only tini (pid 1) and we survive."""
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    me = os.getpid()
    for d in os.listdir("/proc"):
        if d.isdigit() and int(d) not in (1, me):
            try:
                os.kill(int(d), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass


def run_cmd(label, cmd, cwd, env, trace_dir, timeout):
    trace = trace_dir / f"{label}.strace"
    full = ["strace", "-f", "-qq", "-s", "256", "-o", str(trace),
            "-e", "trace=execve,openat,open,connect,sendto,unlink,unlinkat,rename,renameat,renameat2", *cmd]
    t0 = time.time()
    # Own session/process group so a timeout kills strace AND every traced descendant.
    # Output goes to a file, not a pipe: a surviving grandchild holding the pipe can't hang us.
    out_path = trace_dir / f"{label}.out"
    with open(out_path, "wb") as fout:
        p = subprocess.Popen(full, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=fout,
                             stderr=subprocess.STDOUT, start_new_session=True)
        try:
            rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            rc = "timeout"
        _kill_leftovers(p.pid)
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
    out = out_path.read_bytes()[-12000:].decode(errors="replace")[-3000:]
    return {"label": label, "cmd": " ".join(cmd)[:300], "exit": rc, "seconds": round(time.time() - t0, 1),
            "output": out}, trace


def merge(a, b):
    for k, v in b.items():
        if isinstance(v, list):
            seen = {json.dumps(x, sort_keys=True) for x in a.get(k, [])}
            a.setdefault(k, []).extend(x for x in v if json.dumps(x, sort_keys=True) not in seen)
    return a


def main():
    personas = [p for p in os.environ.get("PERSONAS", "developer,ci").split(",") if p in PERSONAS]
    clocks = os.environ.get("CLOCKS", "0,+90d").split(",")
    if not PKG.exists():
        result({"error": "nothing to run: fetch stage produced no package"})
        return
    pj = {}
    if (PKG / "package.json").exists():
        pj = json.loads((PKG / "package.json").read_text())
    runs = []
    for persona in personas:
        for clock in clocks:
            name = f"{persona}{'' if clock == '0' else clock}"
            progress("detonate", f"run {name}: planting honeytokens", run=name)
            base = RUNS / name
            home = base / "home" / PERSONAS[persona]["user"]
            project = base / "project"
            shutil.copytree(PKG, project, symlinks=True)
            home.mkdir(parents=True)
            tokens = honeytokens(home, project, persona)
            env = {"PATH": f"{project}/node_modules/.bin:/usr/local/bin:/usr/bin:/bin", "HOME": str(home),
                   "HOSTNAME": PERSONAS[persona]["host"], "NPM_CONFIG_UPDATE_NOTIFIER": "false",
                   "NPM_CONFIG_AUDIT": "false", "NPM_CONFIG_FUND": "false", "NPM_CONFIG_CACHE": str(base / "npm-cache"),
                   **PERSONAS[persona]["env"]}
            if clock != "0":
                env.update(LD_PRELOAD=FAKETIME_LIB, FAKETIME=clock, FAKETIME_DONT_FAKE_MONOTONIC="1",
                           FAKETIME_NO_CACHE="1")
            trace_dir = base / "traces"
            trace_dir.mkdir()
            steps, traced = [], {}
            for hook in LIFECYCLE:
                cmd = (pj.get("scripts") or {}).get(hook)
                if cmd:
                    progress("detonate", f"run {name}: {hook} script", run=name)
                    step, tr = run_cmd(hook, ["sh", "-c", cmd], project, env, trace_dir, STEP_TIMEOUT)
                    steps.append(step)
                    merge(traced, parse_trace(tr, home, project, tokens))
            if (project / "node_modules").exists():
                progress("detonate", f"run {name}: dependency install scripts", run=name)
                step, tr = run_cmd("deps-rebuild", ["npm", "rebuild", "--foreground-scripts"], project, env,
                                   trace_dir, STEP_TIMEOUT * 2)
                steps.append(step)
                merge(traced, parse_trace(tr, home, project, tokens))
            progress("detonate", f"run {name}: loading entry points", run=name)
            (base / "entry.cjs").write_text(ENTRY_JS)
            step, tr = run_cmd("entry", ["node", str(base / "entry.cjs")], project, env, trace_dir, STEP_TIMEOUT)
            steps.append(step)
            merge(traced, parse_trace(tr, home, project, tokens))
            hits = len(traced.get("honeytoken_access", []))
            progress("detonate", f"run {name}: {hits} honeytoken hits, {len(traced.get('network', []))} network calls",
                     run=name, honeytoken_hits=hits)
            runs.append({"name": name, "persona": persona, "clock": clock, "steps": steps, "observed": traced})
    result({"marker": MARKER, "runs": runs})


if __name__ == "__main__":
    main()
