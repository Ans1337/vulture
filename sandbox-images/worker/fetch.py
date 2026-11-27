"""Stage 1 (network ON, no code execution): fetch the target, pin it, install deps
with --ignore-scripts, then run the static pass.

    fetch.py <source>
source: npm:<name>[@version] | <name>[@version] | https://github.com/<o>/<r>[.git][#ref] | upload
"""
import hashlib, json, os, re, shutil, stat, subprocess, sys, tarfile, zipfile
from pathlib import Path, PurePosixPath
from common import progress, result, fail, parse_source
import static_scan

WORK = Path("/work")
PKG = WORK / "pkg"
MAX_FILES = 20_000                  # per fetched tree (archive members / files after git clone)
MAX_UNPACKED = 500 * 1024 * 1024    # total uncompressed bytes


def sh(cmd, cwd=None, timeout=300, env=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, **env} if env else None)
    if p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {(p.stderr or p.stdout)[-800:]}")
    return p.stdout


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_limits(count, total, what):
    if count > MAX_FILES:
        fail(f"{what} has too many files (more than {MAX_FILES})")
    if total > MAX_UNPACKED:
        fail(f"{what} is too large unpacked (more than {MAX_UNPACKED // 2**20} MB)")


def tar_members(tf):
    """Read the member list, aborting as soon as a limit is crossed (before anything is written)."""
    members, total = [], 0
    for m in tf:
        members.append(m)
        total += m.size if m.isreg() else 0
        check_limits(len(members), total, "archive")
    return members


def check_entry_path(dest, name):
    """Reject (not skip) absolute names and anything that could land outside dest."""
    parts = PurePosixPath(name).parts
    if name.startswith(("/", "\\")) or ".." in parts or not (dest / name).resolve().is_relative_to(dest.resolve()):
        fail(f"archive entry escapes the package directory: {name[:200]!r}")


def safe_extract_tar(tf, dest):
    members = tar_members(tf)
    for m in members:
        check_entry_path(dest, m.name)
        if m.issym() or m.islnk():
            fail(f"archive contains a link: {m.name[:200]!r} -> {m.linkname[:200]!r}")
        if not (m.isreg() or m.isdir()):
            fail(f"archive contains a device or special file: {m.name[:200]!r}")
    for m in members:
        tf.extract(m, dest, set_attrs=False, filter="data") if sys.version_info >= (3, 12) else tf.extract(m, dest)


def fetch_npm(spec):
    progress("fetch", f"npm pack {spec}")
    (WORK / "dl").mkdir(exist_ok=True)
    out = json.loads(sh(["npm", "pack", "--registry=https://registry.npmjs.org/", "--json",
                         "--pack-destination", str(WORK / "dl"), "--", spec]))[0]
    tgz = WORK / "dl" / out["filename"]
    with tarfile.open(tgz) as tf:
        safe_extract_tar(tf, WORK / "dl")
    # usually package/, but some tarballs (e.g. @types/*) use another top-level dir name
    tops = [p for p in (WORK / "dl").iterdir() if p.is_dir()]
    if len(tops) != 1:
        fail(f"unexpected npm tarball layout: {sorted(p.name for p in tops)[:5]}")
    shutil.move(str(tops[0]), PKG)
    return {"type": "npm", "name": out["name"], "version": out["version"], "integrity": out.get("integrity"),
            "sha256": sha256(tgz), "pinned": f"{out['name']}@{out['version']}"}


def fetch_git(url, ref=None):
    progress("fetch", f"git clone {url}" + (f" @ {ref}" if ref else ""))
    git_env = {"GIT_ALLOW_PROTOCOL": "https", "GIT_TERMINAL_PROMPT": "0"}
    sh(["git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "clone", "--depth", "50",
        "--no-recurse-submodules", "--", url + ".git", str(PKG)], timeout=300, env=git_env)
    if ref:
        sh(["git", "-C", str(PKG), "checkout", "--detach", ref, "--"], env=git_env)  # ref can't start with '-'
    commit = sh(["git", "-C", str(PKG), "rev-parse", "HEAD"]).strip()
    tree = sh(["git", "-C", str(PKG), "rev-parse", "HEAD^{tree}"]).strip()
    shutil.rmtree(PKG / ".git", ignore_errors=True)
    count = total = 0
    for d, dirs, files in os.walk(PKG):
        count += len(dirs) + len(files)
        total += sum(os.lstat(os.path.join(d, f)).st_size for f in files)
        check_limits(count, total, "repository")
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
            check_limits(len(z.infolist()), sum(i.file_size for i in z.infolist()), "archive")
            for i in z.infolist():
                check_entry_path(PKG, i.filename)
                kind = stat.S_IFMT(i.external_attr >> 16)  # unix mode, 0 for DOS/Windows zips
                if kind == stat.S_IFLNK:
                    fail(f"archive contains a link: {i.filename[:200]!r}")
                if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                    fail(f"archive contains a device or special file: {i.filename[:200]!r}")
            z.extractall(PKG)
    else:
        shutil.copy(f, PKG / f.name)
    # macOS tar/zip add AppleDouble files (._*) and __MACOSX/; drop them so the package root is found
    for junk in [*PKG.rglob("._*"), *PKG.rglob("__MACOSX")]:
        if junk.is_dir():
            shutil.rmtree(junk, ignore_errors=True)
        elif junk.exists():
            junk.unlink()
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
        else:
            try:
                kind, spec, ref = parse_source(src)
            except ValueError as e:
                fail(str(e))
            meta = fetch_git(spec, ref) if kind == "git" else fetch_npm(spec)
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
