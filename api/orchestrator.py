"""Runs one scan through isolated containers. The API process never executes the package.

fetch    -> worker container, normal network (downloads only, no install scripts run)
sandbox  -> private internal Docker network with no route out + sinkhole (fake internet)
detonate -> worker container on that network only, read-only rootfs, no capabilities
"""
from __future__ import annotations

import io
import json
import os
import secrets
import tarfile
import threading
import time
from typing import Callable, Optional

import docker

WORKER_IMAGE = os.environ.get("WORKER_IMAGE", "vulture-worker:latest")
SINKHOLE_IMAGE = os.environ.get("SINKHOLE_IMAGE", "vulture-sinkhole:latest")
PERSONAS = os.environ.get("SCAN_PERSONAS", "developer,ci")
CLOCKS = os.environ.get("SCAN_CLOCKS", "0,+90d")
STEP_TIMEOUT = os.environ.get("SCAN_STEP_TIMEOUT", "60")

Emit = Callable[[str, str, dict], None]  # (stage, message, data)


def _stream(container, emit: Emit, timeout: int) -> dict:
    """Follow PROGRESS/RESULT lines from a worker container."""
    result: dict = {}
    deadline = time.time() + timeout

    def watchdog():
        while time.time() < deadline:
            time.sleep(2)
            try:
                container.reload()
                if container.status == "exited":
                    return
            except Exception:
                return
        try:
            container.kill()
        except Exception:
            pass

    threading.Thread(target=watchdog, daemon=True).start()
    buf = b""
    for chunk in container.logs(stream=True, follow=True):
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            text = line.decode(errors="replace")
            if text.startswith("PROGRESS "):
                d = json.loads(text[9:])
                emit(d.pop("stage"), d.pop("msg"), d)
            elif text.startswith("RESULT "):
                result = json.loads(text[7:])
    if not result:
        result = {"error": "worker produced no result (timed out or crashed)"}
    return result


def run_scan(scan_id: str, source: str, upload: Optional[tuple[str, bytes]], emit: Emit) -> dict:
    client = docker.from_env()
    vol = client.volumes.create(f"vulture-scan-{scan_id}")
    net = None
    created = []
    marker = "VLT" + secrets.token_hex(6).upper()
    try:
        # 1-2. Fetch + static pass (network on, nothing executed)
        emit("fetch", f"fetching {source}", {})
        fetch = client.containers.create(
            WORKER_IMAGE, ["/opt/scan/fetch.py", "upload" if upload else source],
            volumes={vol.name: {"bind": "/work", "mode": "rw"}},
            mem_limit="1g", pids_limit=512, cap_drop=["ALL"], security_opt=["no-new-privileges"],
            labels={"vulture.scan": scan_id})
        created.append(fetch)
        if upload:
            name, data = upload
            tar = io.BytesIO()
            with tarfile.open(fileobj=tar, mode="w") as tf:
                d = tarfile.TarInfo("upload"); d.type = tarfile.DIRTYPE; d.mode = 0o777
                tf.addfile(d)
                info = tarfile.TarInfo(f"upload/{os.path.basename(name)}"); info.size = len(data); info.mode = 0o644
                tf.addfile(info, io.BytesIO(data))
            fetch.put_archive("/work", tar.getvalue())
        fetch.start()
        fetched = _stream(fetch, emit, 900)
        if fetched.get("error"):
            raise RuntimeError(fetched["error"])

        # 3. Sandbox: internal network (no internet) + sinkhole that answers back
        emit("sandbox", "building isolated network + fake internet", {})
        net = client.networks.create(f"vulture-scan-{scan_id}", driver="bridge", internal=True,
                                     labels={"vulture.scan": scan_id})
        sink = client.containers.run(SINKHOLE_IMAGE, detach=True, network=net.name,
                                     name=f"vulture-sink-{scan_id}", labels={"vulture.scan": scan_id},
                                     mem_limit="256m")
        created.append(sink)
        sink_ip = None
        for _ in range(30):
            sink.reload()
            sink_ip = sink.attrs["NetworkSettings"]["Networks"][net.name]["IPAddress"]
            if sink_ip and b'"ready"' in sink.logs():
                break
            time.sleep(0.5)
        emit("sandbox", f"sinkhole up at {sink_ip}; honeytoken marker {marker}",
             {"personas": PERSONAS.split(","), "clocks": CLOCKS.split(",")})

        # 4-5. Detonate + observe
        det = client.containers.create(
            WORKER_IMAGE, ["/opt/scan/detonate.py"], network=net.name, dns=[sink_ip],
            environment={"MARKER": marker, "PERSONAS": PERSONAS, "CLOCKS": CLOCKS, "STEP_TIMEOUT": STEP_TIMEOUT},
            volumes={vol.name: {"bind": "/work", "mode": "ro"}},
            read_only=True, tmpfs={"/tmp": "rw,exec,size=1g,uid=1000"},
            mem_limit="1g", nano_cpus=2_000_000_000, pids_limit=512,
            cap_drop=["ALL"], security_opt=["no-new-privileges"], labels={"vulture.scan": scan_id})
        created.append(det)
        det.start()
        detonated = _stream(det, emit, 1800)

        sink_log = []
        for line in sink.logs().decode(errors="replace").splitlines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("kind") not in ("ready",):
                sink_log.append(ev)
        emit("observe", f"{len(sink_log)} events caught by the fake internet", {})
        return {"marker": marker, "fetch": fetched, "detonate": detonated, "sinkhole": sink_log}
    finally:
        for c in created:
            try:
                c.remove(force=True)
            except Exception:
                pass
        if net is not None:
            try:
                net.remove()
            except Exception:
                pass
        try:
            vol.remove(force=True)
        except Exception:
            pass
