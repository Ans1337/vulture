"""Stage 1 (network ON, no code execution): fetch the target, pin it, install deps
with --ignore-scripts, then run the static pass.

    fetch.py <source>
source: npm:<name>[@version] | <name>[@version] | https://github.com/<o>/<r>[.git][#ref] | upload
"""
import hashlib, json, os, re, shutil, subprocess, sys, tarfile, zipfile
from pathlib import Path
from common import progress, result, fail
import static_scan

WORK = Path("/work")
PKG = WORK / "pkg"


def sh(cmd, cwd=None, timeout=300):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {(p.stderr or p.stdout)[-800:]}")
    return p.stdout


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_extract_tar(tf, dest):
    for m in tf.getmembers():
        target = (dest / m.name).resolve()
        if not str(target).startswith(str(dest.resolve())) or m.issym() or m.islnk() or m.isdev():
            continue
        tf.extract(m, dest, set_attrs=False, filter="data") if sys.version_info >= (3, 12) else tf.extract(m, dest)


def fetch_npm(spec):
    progress("fetch", f"npm pack {spec}")
    (WORK / "dl").mkdir(exist_ok=True)
    out = json.loads(sh(["npm", "pack", spec, "--json", "--pack-destination", str(WORK / "dl")]))[0]
    tgz = WORK / "dl" / out["filename"]
    with tarfile.open(tgz) as tf:
        safe_extract_tar(tf, WORK / "dl")
    shutil.move(str(WORK / "dl" / "package"), PKG)
    return {"type": "npm", "name": out["name"], "version": out["version"], "integrity": out.get("integrity"),
            "sha256": sha256(tgz), "pinned": f"{out['name']}@{out['version']}"}


def fetch_git(url):
    ref = None
    if "#" in url:
        url, ref = url.split("#", 1)
    if not re.match(r"^https://[\w.-]+/[\w.-]+/[\w.-]+(\.git)?/?$", url):
        fail("only https git URLs like https://github.com/owner/repo are accepted")
    progress("fetch", f"git clone {url}" + (f" @ {ref}" if ref else ""))
    sh(["git", "clone", "--depth", "50", "--no-recurse-submodules", url, str(PKG)], timeout=300)
    if ref:
        sh(["git", "-C", str(PKG), "checkout", "--detach", ref])
    commit = sh(["git", "-C", str(PKG), "rev-parse", "HEAD"]).strip()
    tree = sh(["git", "-C", str(PKG), "rev-parse", "HEAD^{tree}"]).strip()
    shutil.rmtree(PKG / ".git", ignore_errors=True)
    name = version = None
    if (PKG / "package.json").exists():
        pj = json.loads((PKG / "package.json").read_text())
        name, version = pj.get("name"), pj.get("version")
    return {"type": "git", "url": url, "commit": commit, "tree": tree, "name": name, "version": version,
            "pinned": f"{url}#{commit}"}


def fetch_upload():
    files = [p for p in (WORK / "upload").glob("*") if p.is_file()]
    if not files:
        fail("no uploaded file")
    f = files[0]
    progress("fetch", f"unpacking upload {f.name}")
    PKG.mkdir()
    if f.name.endswith((".tgz", ".tar.gz", ".tar")):
        with tarfile.open(f) as tf:
            safe_extract_tar(tf, PKG)
    elif f.name.endswith(".zip"):
        with zipfile.ZipFile(f) as z:
            for n in z.namelist():
                t = (PKG / n).resolve()
                if str(t).startswith(str(PKG.resolve())):
                    z.extract(n, PKG)
    else:
        shutil.copy(f, PKG / f.name)
    # npm tarballs nest everything under package/
    kids = list(PKG.iterdir())
    if len(kids) == 1 and kids[0].is_dir():
        inner = kids[0]
        for c in inner.iterdir():
            shutil.move(str(c), PKG)
        inner.rmdir()
    name = version = None
    if (PKG / "package.json").exists():
        pj = json.loads((PKG / "package.json").read_text())
        name, version = pj.get("name"), pj.get("version")
    return {"type": "upload", "filename": f.name, "sha256": sha256(f), "name": name, "version": version,
            "pinned": f"sha256:{sha256(f)}"}


def main():
    src = sys.argv[1].strip()
    try:
        if src == "upload":
            meta = fetch_upload()
        elif src.startswith("https://"):
            meta = fetch_git(src)
        else:
            meta = fetch_npm(src[4:] if src.startswith("npm:") else src)
    except Exception as e:
        fail(f"fetch failed: {e}")
    progress("fetch", f"pinned {meta['pinned']}", meta=meta)

    deps = {}
    if (PKG / "package.json").exists():
        progress("fetch", "installing dependencies with --ignore-scripts (nothing executes yet)")
        try:
            sh(["npm", "install", "--ignore-scripts", "--omit=dev", "--no-package-lock", "--loglevel=error"],
               cwd=PKG, timeout=600)
        except Exception as e:
            progress("fetch", f"dependency install incomplete: {str(e)[:200]}")
        lock = PKG / "node_modules" / ".package-lock.json"
        if lock.exists():
            for path, info in json.loads(lock.read_text()).get("packages", {}).items():
                deps[path.removeprefix("node_modules/")] = {"version": info.get("version"),
                                                           "integrity": info.get("integrity")}
    meta["dependencies"] = deps

    progress("static", "scanning source")
    static = static_scan.scan(PKG)
    progress("static", f"{len(static['findings'])} findings, {len(static['install_scripts'])} install scripts",
             summary=static["summary"])
    result({"meta": meta, "static": static})


if __name__ == "__main__":
    main()
