"""Read-only helper the AI investigator runs in a throwaway container (no network, read-only volume).

    inspect_tool.py ls [relpath]  |  read <relpath>  |  grep <regex>

Everything is confined to /work/pkg and output is capped, so a hostile package can't make the
investigator read anything else or flood it.
"""
import os, re, sys
from pathlib import Path

ROOT = Path("/work/pkg").resolve()
MAX_OUT = 12000


def inside(rel: str) -> Path:
    p = (ROOT / rel.lstrip("/")).resolve()
    if p != ROOT and ROOT not in p.parents:
        sys.exit("path is outside the package")
    return p


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: ls|read|grep")
    cmd, arg = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
    if cmd == "ls":
        p = inside(arg or ".")
        out = [f"{'d' if c.is_dir() else '-'} {c.relative_to(ROOT)}" for c in sorted(p.iterdir())[:300]]
    elif cmd == "read":
        p = inside(arg)
        if not p.is_file():
            sys.exit("not a file")
        out = [p.read_bytes()[:MAX_OUT].decode("utf-8", "replace")]
    elif cmd == "grep":
        try:
            rx = re.compile(arg[:200])
        except re.error as e:
            sys.exit(f"bad regex: {e}")
        out = []
        for dp, _, files in os.walk(ROOT):
            for f in files:
                fp = Path(dp) / f
                try:
                    if fp.stat().st_size > 2_000_000:
                        continue
                    for n, line in enumerate(fp.read_text("utf-8", "replace").splitlines(), 1):
                        if rx.search(line):
                            out.append(f"{fp.relative_to(ROOT)}:{n}: {line.strip()[:200]}")
                            if len(out) >= 60:
                                raise StopIteration
                except StopIteration:
                    break
                except OSError:
                    pass
            if len(out) >= 60:
                break
    else:
        sys.exit("unknown command")
    print("\n".join(out)[:MAX_OUT] or "(nothing)")


main()
