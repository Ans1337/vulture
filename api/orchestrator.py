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
import logging

import investigator
import lifecycle
import vultr
from limits import LIMITS as L

WORKER_IMAGE = os.environ.get("WORKER_IMAGE", "vulture-worker:latest")
SINKHOLE_IMAGE = os.environ.get("SINKHOLE_IMAGE", "vulture-sinkhole:latest")
PERSONAS = os.environ.get("SCAN_PERSONAS", "developer,ci")
CLOCKS = os.environ.get("SCAN_CLOCKS", "0,+90d")
STEP_TIMEOUT = str(L.step_timeout)
# no-new-privileges blocks every exec on hosts where AppArmor can't transition under it
# (e.g. Docker installed via snap). Set SANDBOX_NO_NEW_PRIVILEGES=0 there; the worker image
# has no setuid binaries and all capabilities are dropped, so the sandbox stays locked down.
SECURITY_OPT = ["no-new-privileges"] if os.environ.get("SANDBOX_NO_NEW_PRIVILEGES", "1") != "0" else []

class Cancelled(Exception):
    """The user cancelled the scan; everything is torn down and the scan is marked cancelled."""


class UserFacingError(Exception):
    """A failure whose message is safe and useful to show the user (e.g. "npm package not found")."""


log = logging.getLogger("vulture.orchestrator")
Emit = Callable[[str, str, dict], None]  # (stage, message, data)


def _stream(container, emit: Emit, timeout: int, cancel=None) -> dict:
    """Follow PROGRESS/RESULT lines from a worker container."""
    result: dict = {}
    deadline = time.time() + max(1, timeout)
    timed_out = threading.Event()

    def watchdog():
        while time.time() < deadline:
            time.sleep(1)
            if cancel is not None and cancel.is_set():
                break
            try:
                container.reload()
                if container.status == "exited":
                    return
            except Exception:
                return
        # Deadline hit (or cancelled): remove at once so nothing keeps running until the finally-cleanup.
        if cancel is None or not cancel.is_set():
            timed_out.set()
        try:
            container.remove(force=True)
        except Exception:
            pass

    threading.Thread(target=watchdog, daemon=True).start()
    buf = b""
    other: list[str] = []  # anything that isn't PROGRESS/RESULT (tracebacks, npm errors)
    try:
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
                elif text.strip():
                    other = (other + [text])[-15:]
    except (docker.errors.APIError, docker.errors.NotFound, OSError):
        if time.time() < deadline and not (cancel is not None and cancel.is_set()):
            raise  # only swallow the stream breaking because the watchdog removed the container
    oom = False
    try:
        container.reload()
        oom = bool(container.attrs.get("State", {}).get("OOMKilled"))
    except Exception:
        pass
    if not result:
        try:
            container.reload()
            code = container.attrs.get("State", {}).get("ExitCode")
        except Exception:
            code = "?"
        tail = "\n".join(other[-10:]) or "(no output)"
        why = (f"killed after hitting the {timeout}s time limit" if timed_out.is_set()
               else "killed for exceeding its memory limit" if oom else f"exit code {code}")
        result = {"error": f"worker produced no result ({why}). Last output:\n{tail}", "internal": True}
    if timed_out.is_set():
        result["limit_hit"] = "time"
    elif oom:
        result["limit_hit"] = "memory"
    return result


def _run_in(client, scan_id: str, source: str, upload: Optional[tuple[str, bytes]], emit: Emit, cancel,
            investigate) -> dict:
    """One scan = one throwaway environment. Hard caps on time and memory; destroyed in `finally`."""
    started = time.time()
    labels = {lifecycle.LABEL: scan_id}
    marker = "VLT" + secrets.token_hex(6).upper()

    def remaining(stage_cap: int) -> int:
        """Seconds this stage may run: its own cap, but never past the scan-wide deadline."""
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        left = int(L.scan_timeout - (time.time() - started))
        if left <= 0:
            raise TimeoutError(f"scan exceeded its {L.scan_timeout}s total time limit")
        return min(stage_cap, left)

    emit("sandbox", "resource limits", {"limits": L.as_dict()})
    vol = client.volumes.create(f"vulture-scan-{scan_id}", labels=labels)
    net = None
    try:
        # 1-2. Fetch + static pass (network on, nothing executed)
        emit("fetch", f"fetching {source}", {})
        fetch = client.containers.create(
            WORKER_IMAGE, ["/opt/scan/fetch.py", "upload" if upload else source],
            volumes={vol.name: {"bind": "/work", "mode": "rw"}},
            mem_limit=L.fetch_mem, memswap_limit=L.fetch_mem, nano_cpus=L.nano(L.fetch_cpus),
            pids_limit=L.pids, cap_drop=["ALL"], security_opt=SECURITY_OPT, labels=labels)
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
        fetched = _stream(fetch, emit, remaining(L.fetch_timeout), cancel)
        if fetched.get("error"):
            if fetched.get("internal"):
                raise RuntimeError(fetched["error"])           # worker crashed: detail stays in the server log
            raise UserFacingError(fetched["error"])            # worker reported a clean reason

        # 3. Sandbox: internal network (no internet) + sinkhole that answers back
        emit("sandbox", "building isolated network + fake internet", {})
        net = client.networks.create(f"vulture-scan-{scan_id}", driver="bridge", internal=True, labels=labels)
        sink = client.containers.run(
            SINKHOLE_IMAGE, detach=True, network=net.name, name=f"vulture-sink-{scan_id}", labels=labels,
            mem_limit=L.sinkhole_mem, memswap_limit=L.sinkhole_mem, nano_cpus=L.nano(L.sinkhole_cpus),
            pids_limit=min(L.pids, 128), user="1000:1000", cap_drop=["ALL"], security_opt=SECURITY_OPT,
            read_only=True,
            # bind 53/80/443/... as non-root without CAP_NET_BIND_SERVICE
            sysctls={"net.ipv4.ip_unprivileged_port_start": "0"})
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
            read_only=True, tmpfs={"/tmp": f"rw,exec,size={L.tmpfs_size},uid=1000"},
            mem_limit=L.detonate_mem, memswap_limit=L.detonate_mem, nano_cpus=L.nano(L.detonate_cpus),
            pids_limit=L.pids, cap_drop=["ALL"], security_opt=SECURITY_OPT, labels=labels)
        det.start()
        detonated = _stream(det, emit, remaining(L.detonate_timeout), cancel)
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        if detonated.get("limit_hit"):
            emit("detonate", f"run stopped: {detonated['limit_hit']} limit hit "
                 "(a package that exhausts its sandbox is itself a finding)", {"limit_hit": detonated["limit_hit"]})

        sink_log = []
        for line in sink.logs().decode(errors="replace").splitlines():
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("kind") not in ("ready",):
                sink_log.append(ev)
        emit("observe", f"{len(sink_log)} events caught by the fake internet", {})
        raw = {"marker": marker, "fetch": fetched, "detonate": detonated, "sinkhole": sink_log}

        # 5b. The AI investigator may poke around and re-run the package while the sandbox is still alive.
        if investigate is not None:
            ctx = Investigation(client, vol.name, net.name, sink, sink_ip, marker, fetched, labels, remaining, cancel)
            try:
                raw["investigation"] = investigate(ctx, raw, emit)
            except Cancelled:
                raise
            except Exception:
                log.exception("investigator failed")
                emit("investigate", "investigator stopped early (internal error); continuing with the evidence so far", {})
        return raw
    finally:
        # Lifecycle: the environment never outlives the scan. Found by label, then verified gone.
        try:
            report = lifecycle.teardown(client, scan_id)
        except Exception:                      # e.g. the remote VM is already gone; the VM destroy covers it
            log.exception("teardown failed")
            report = {"containers": 0, "networks": 0, "volumes": 0, "destroyed": False, "leftover": ["(teardown error)"]}
        emit("destroy", "sandbox destroyed: " + (
            f"{report['containers']} containers, {report['networks']} network, {report['volumes']} volume removed"
            if report["destroyed"] else f"FAILED, leftover: {', '.join(report['leftover'])}"),
            {"lifecycle": report, "elapsed_s": round(time.time() - started, 1)})


class Investigation:
    """What the AI investigator may do while the sandbox is alive. All of it runs in labelled,
    resource-capped containers, so it is torn down with the scan."""

    def __init__(self, client, vol, net, sink, sink_ip, marker, fetched, labels, remaining, cancel):
        self.client, self.vol, self.net, self.sink, self.sink_ip = client, vol, net, sink, sink_ip
        self.marker, self.fetched, self.labels, self.remaining, self.cancel = marker, fetched, labels, remaining, cancel
        self._seen_sink = len(sink.logs().decode(errors="replace").splitlines())

    def cancelled(self) -> bool:
        return self.cancel is not None and self.cancel.is_set()

    def inspect(self, cmd: str, arg: str) -> str:
        """Read-only look at the package: no network, read-only volume, tiny limits, short deadline."""
        c = self.client.containers.create(
            WORKER_IMAGE, ["/opt/scan/inspect_tool.py", cmd, arg] if arg else ["/opt/scan/inspect_tool.py", cmd],
            network_mode="none", volumes={self.vol: {"bind": "/work", "mode": "ro"}}, read_only=True,
            mem_limit="128m", memswap_limit="128m", nano_cpus=L.nano(0.5), pids_limit=64,
            cap_drop=["ALL"], security_opt=SECURITY_OPT, labels=self.labels)
        c.start()
        try:
            c.wait(timeout=min(30, max(1, self.remaining(30))))
        except Exception:
            c.kill()
        return c.logs(stdout=True, stderr=True).decode(errors="replace")[:12000]

    def rerun(self, persona: str, clock: str) -> dict:
        """One more detonation: a single persona x clock, same isolation as the first."""
        det = self.client.containers.create(
            WORKER_IMAGE, ["/opt/scan/detonate.py"], network=self.net, dns=[self.sink_ip],
            environment={"MARKER": self.marker, "PERSONAS": persona, "CLOCKS": clock, "STEP_TIMEOUT": STEP_TIMEOUT},
            volumes={self.vol: {"bind": "/work", "mode": "ro"}},
            read_only=True, tmpfs={"/tmp": f"rw,exec,size={L.tmpfs_size},uid=1000"},
            mem_limit=L.detonate_mem, memswap_limit=L.detonate_mem, nano_cpus=L.nano(L.detonate_cpus),
            pids_limit=L.pids, cap_drop=["ALL"], security_opt=SECURITY_OPT, labels=self.labels)
        det.start()
        res = _stream(det, lambda *a: None, self.remaining(min(L.detonate_timeout, 300)), self.cancel)
        lines = self.sink.logs().decode(errors="replace").splitlines()
        new, self._seen_sink = lines[self._seen_sink:], len(lines)
        events = []
        for line in new:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("kind") != "ready":
                events.append(ev)
        import analyze
        e = analyze.evidence({"marker": self.marker, "fetch": self.fetched, "detonate": res, "sinkhole": events})
        return {"persona": persona, "clock": clock, "error": res.get("error"), "honeytoken_access": e["honeytoken_access"][:15],
                "exfiltration": e["exfiltration"][:10], "dns_lookups": e["dns_lookups"][:15],
                "processes": e["processes"][:15], "requests": e["requests"][:10]}


def run_scan(scan_id: str, source: str, upload: Optional[tuple[str, bytes]], emit: Emit,
             cancel=None, mode: str = "docker", investigate=investigator.investigate) -> dict:
    """mode "docker": sandbox containers on this host's Docker (via the filtered proxy).
    mode "vultr": same code against the Docker daemon of a throwaway Vultr VM that is destroyed afterwards."""
    if mode == "vultr":
        with vultr.Sandbox(scan_id, emit, cancel) as remote:
            return _run_in(remote, scan_id, source, upload, emit, cancel, investigate)
    return _run_in(docker.from_env(), scan_id, source, upload, emit, cancel, investigate)
