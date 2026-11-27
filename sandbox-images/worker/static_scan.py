"""Static pass: install scripts, obfuscation, encoded payloads and risky capabilities."""
import json, math, re
from collections import Counter
from pathlib import Path

CODE_EXT = {".js", ".cjs", ".mjs", ".ts", ".jsx", ".tsx", ".sh", ".py", ".ps1", ".bat", ".cmd"}
MAX_FILE = 2_000_000
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preuninstall", "postuninstall")

# (id, severity, capability, regex)
RULES = [
    ("child_process", "high", "shell-out", r"require\(\s*['\"](node:)?child_process['\"]\s*\)|from\s+['\"](node:)?child_process['\"]"),
    ("exec_call", "medium", "shell-out", r"\b(execSync|spawnSync|execFile|spawn|exec)\s*\("),
    ("eval", "high", "dynamic-code", r"(?<![\w.])eval\s*\("),
    ("new_function", "high", "dynamic-code", r"new\s+Function\s*\("),
    ("vm_run", "medium", "dynamic-code", r"\bvm\.(runInNewContext|runInThisContext|Script)\b"),
    ("base64_decode", "medium", "encoded-payload", r"Buffer\.from\([^)]{0,200},\s*['\"]base64['\"]\)|\batob\s*\("),
    ("hex_decode", "medium", "encoded-payload", r"Buffer\.from\([^)]{0,200},\s*['\"]hex['\"]\)"),
    ("env_access", "low", "env-access", r"process\.env(\.[A-Z_][A-Z0-9_]*|\[)"),
    ("env_dump", "high", "env-access", r"(JSON\.stringify|Object\.(keys|entries))\(\s*process\.env\s*\)"),
    ("net_module", "medium", "network", r"require\(\s*['\"](node:)?(http|https|net|dgram|dns|tls)['\"]\s*\)|from\s+['\"](node:)?(http|https|net|dgram|dns|tls)['\"]"),
    ("fetch_call", "low", "network", r"\bfetch\s*\(\s*['\"`]https?://"),
    ("raw_url", "low", "network", r"https?://(?!(www\.)?(github\.com|npmjs\.(com|org)|nodejs\.org|registry\.npmjs\.org|opensource\.org|mozilla\.org|w3\.org|apache\.org|json-schema\.org)\b)[\w.-]+\.[a-z]{2,}[^\s'\"`)]*"),
    ("ip_literal", "medium", "network", r"['\"`](\d{1,3}\.){3}\d{1,3}(:\d+)?['\"`/]"),
    ("discord_webhook", "high", "exfil", r"discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com|ngrok\.(io|app)|webhook\.site|requestbin|pipedream\.net|interact\.sh|burpcollaborator"),
    ("secret_paths", "high", "credential-access", r"\.ssh/|id_rsa|\.npmrc|\.aws/credentials|\.git-credentials|\.docker/config\.json|\.kube/config|Local State|Login Data|\.config/solana|keystore|wallet\.dat|\.env\b"),
    ("homedir", "low", "credential-access", r"os\.homedir\(\)|process\.env\.HOME\b|USERPROFILE"),
    ("crypto_wallet", "medium", "credential-access", r"metamask|phantom|exodus|electrum|seed phrase|mnemonic"),
    ("fs_write_startup", "high", "persistence", r"\.bashrc|\.zshrc|\.profile|crontab|LaunchAgents|\\\\Startup\\\\|systemd/system"),
    ("time_bomb", "medium", "evasion", r"new Date\(\)\s*[<>]=?\s*new Date\(|Date\.now\(\)\s*[<>]=?\s*\d{12,}|getFullYear\(\)\s*[<>]=?\s*20\d\d"),
    ("ci_check", "medium", "evasion", r"process\.env\.(CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|TRAVIS|BUILDKITE)\b"),
    ("os_check", "low", "evasion", r"os\.(platform|hostname|userInfo|type)\(\)|process\.platform"),
    ("obfuscator_ids", "high", "obfuscation", r"\b_0x[0-9a-f]{4,}\b"),
    ("chained_fromcharcode", "medium", "obfuscation", r"String\.fromCharCode\((\s*\d+\s*,){8,}"),
]
COMPILED = [(i, s, c, re.compile(r, re.I if i in ("secret_paths", "crypto_wallet") else 0)) for i, s, c, r in RULES]
LONG_B64 = re.compile(r"['\"`]([A-Za-z0-9+/]{200,}={0,2})['\"`]")
LONG_HEX = re.compile(r"['\"`]((?:\\x[0-9a-fA-F]{2}|[0-9a-fA-F]{2}){100,})['\"`]")


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def scan_file(path, rel, findings):
    try:
        text = path.read_text(errors="replace")
    except Exception:
        return
    lines = text.splitlines() or [""]
    avg_len = len(text) / max(len(lines), 1)
    if avg_len > 400 and len(text) > 5000 and not rel.endswith(".min.js"):
        findings.append({"rule": "minified_or_packed", "severity": "medium", "capability": "obfuscation",
                         "file": rel, "line": 1, "snippet": f"avg line length {avg_len:.0f}, entropy {entropy(text[:20000]):.2f}"})
    for no, line in enumerate(lines, 1):
        if len(line) > 4000:
            line = line[:4000]
        for rid, sev, cap, rx in COMPILED:
            m = rx.search(line)
            if m:
                findings.append({"rule": rid, "severity": sev, "capability": cap, "file": rel, "line": no,
                                 "snippet": line.strip()[:200]})
        for rx, rid in ((LONG_B64, "long_base64_blob"), (LONG_HEX, "long_hex_blob")):
            m = rx.search(line)
            if m:
                findings.append({"rule": rid, "severity": "high", "capability": "encoded-payload", "file": rel,
                                 "line": no, "snippet": m.group(1)[:80] + "…",
                                 "entropy": round(entropy(m.group(1)), 2)})


def scan(root: Path):
    root = Path(root)
    findings, install_scripts, files = [], [], 0
    for pj in [root / "package.json", *root.glob("node_modules/**/package.json")]:
        if "node_modules" in pj.relative_to(root).parts[:-1] and pj.parent.name == "node_modules":
            continue
        try:
            data = json.loads(pj.read_text())
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for hook in LIFECYCLE:
            cmd = (data.get("scripts") or {}).get(hook)
            if cmd and not (hook == "prepare" and pj.parent != root):
                install_scripts.append({"package": data.get("name") or str(pj.parent.relative_to(root)),
                                        "is_root": pj.parent == root, "hook": hook, "command": cmd[:300]})
    # Code: the package itself fully, dependencies only where they have install scripts.
    dep_dirs = {s["package"] for s in install_scripts if not s["is_root"]}
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix not in CODE_EXT or p.stat().st_size > MAX_FILE:
            continue
        rel = str(p.relative_to(root))
        parts = p.relative_to(root).parts
        if "node_modules" in parts:
            idx = len(parts) - 1 - list(reversed(parts)).index("node_modules")
            pkg = "/".join(parts[idx + 1: idx + 3 if parts[idx + 1].startswith("@") else idx + 2])
            if pkg not in dep_dirs:
                continue
        files += 1
        scan_file(p, rel, findings)
    # Shrink noise: keep at most 5 hits per rule per file.
    seen, kept = Counter(), []
    for f in findings:
        k = (f["rule"], f["file"])
        seen[k] += 1
        if seen[k] <= 5:
            kept.append(f)
    sev = Counter(f["severity"] for f in kept)
    caps = sorted({f["capability"] for f in kept})
    return {"files_scanned": files, "install_scripts": install_scripts, "findings": kept[:400],
            "summary": {"high": sev["high"], "medium": sev["medium"], "low": sev["low"], "capabilities": caps}}


if __name__ == "__main__":
    import sys
    print(json.dumps(scan(Path(sys.argv[1])), indent=2))
