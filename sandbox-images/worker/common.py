import json, re, sys

def progress(stage, msg, **data):
    """One line of progress the orchestrator streams to the dashboard."""
    print("PROGRESS " + json.dumps({"stage": stage, "msg": msg, **data}), flush=True)

def result(obj):
    print("RESULT " + json.dumps(obj), flush=True)

def fail(msg):
    print("RESULT " + json.dumps({"error": msg}), flush=True)
    sys.exit(1)

# Accepted sources (keep in sync with api/app.py): an npm name (lowercase, url-safe, optional @scope/)
# with an optional exact version or dist-tag, or a GitHub repo URL with an optional #ref.
NPM_RE = re.compile(r"^(?:npm:)?((?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*)"
                    r"(?:@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?|[A-Za-z0-9][A-Za-z0-9._-]*))?$")
GITHUB_RE = re.compile(r"^https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]{1,100}?)"
                       r"(?:\.git)?/?(?:#([A-Za-z0-9._][A-Za-z0-9._/-]{0,199}))?$")
SOURCE_HELP = ("unsupported source: give an npm package name (name, @scope/name, name@1.2.3, name@latest) "
               "or a GitHub URL (https://github.com/owner/repo[#ref])")


def parse_source(src):
    """-> ("npm", "name[@version]", None) | ("git", "https://github.com/o/r", ref|None); ValueError otherwise."""
    m = NPM_RE.fullmatch(src)
    if m and len(m.group(1)) <= 214:
        return ("npm", m.group(1) + (f"@{m.group(2)}" if m.group(2) else ""), None)
    m = GITHUB_RE.fullmatch(src)
    if m and m.group(2) not in (".", "..") and ".." not in (m.group(3) or ""):
        return ("git", f"https://github.com/{m.group(1)}/{m.group(2)}", m.group(3))
    raise ValueError(SOURCE_HELP)
