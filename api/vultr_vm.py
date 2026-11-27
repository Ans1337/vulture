"""Throwaway Vultr VM per scan (SANDBOX_MODE=vultr).

For each scan this module:
  1. creates a small Vultr instance tagged `vulture-scan`, behind a firewall group that only
     lets SSH in from VULTR_SSH_ALLOW_CIDR (the app VM),
  2. gives it a one-off SSH login key *and* a one-off SSH host key (both generated here and passed
     through cloud-init), so the connection is pinned and nothing is trusted on first use,
  3. waits for cloud-init to install Docker (listening on the VM's 127.0.0.1:2375 only),
  4. tunnels that Docker socket over SSH and hands a normal `docker.DockerClient` to the
     orchestrator, which runs the same fetch / sandbox / detonate steps it runs locally,
  5. cuts all outbound traffic on the VM before detonation (Vultr firewalls are inbound-only),
  6. deletes the instance, whatever happened.

A janitor deletes `vulture-scan` instances older than VULTR_MAX_AGE_MIN (crashes, restarts).
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import select
import socket
import tarfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator, Optional

API = "https://api.vultr.com/v2"
TAG = "vulture-scan"
FIREWALL_DESC = "vulture-scan: ssh from app VM only"


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


REGION = _env("VULTR_REGION", "sto")             # Stockholm; any region id from GET /v2/regions
PLAN = _env("VULTR_PLAN", "vc2-2c-4gb")          # building the worker image wants >= 2 GB RAM
OS_ID = int(_env("VULTR_OS_ID", "2284"))         # Ubuntu 24.04 x64
SNAPSHOT_ID = _env("VULTR_SNAPSHOT_ID")          # optional pre-baked image with Docker + images
BOOT_TIMEOUT = int(_env("VULTR_BOOT_TIMEOUT", "600"))
MAX_AGE_MIN = int(_env("VULTR_MAX_AGE_MIN", "60"))
MAX_VMS = int(_env("VULTR_MAX_VMS", "3"))
SSH_PORT = int(_env("VULTR_SSH_PORT", "22"))  # only changed by the local end-to-end test
IMAGES_DIR = Path(_env("SANDBOX_IMAGES_DIR") or Path(__file__).resolve().parent.parent / "sandbox-images")

Emit = Callable[[str, str, dict], None]
_vm_slots = threading.BoundedSemaphore(MAX_VMS)


class VultrError(RuntimeError):
    pass


# --------------------------------------------------------------------------- Vultr API

def _api(method: str, path: str, body: Optional[dict] = None, ok=(200, 201, 202, 204)) -> dict:
    key = _env("VULTR_API_KEY")
    if not key:
        raise VultrError("SANDBOX_MODE=vultr needs VULTR_API_KEY in .env")
    req = urllib.request.Request(
        API + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        # Vultr error bodies are {"error": "...", "status": n}; never echo request headers.
        try:
            msg = json.loads(e.read() or b"{}").get("error", "")
        except ValueError:
            msg = ""
        raise VultrError(f"Vultr API {method} {path.split('?')[0]} -> HTTP {e.code} {msg}".strip()) from None
    if status not in ok:
        raise VultrError(f"Vultr API {method} {path} -> HTTP {status}")
    return json.loads(raw) if raw else {}


def _firewall_group() -> str:
    """One shared firewall group: inbound TCP 22 from the app VM only, everything else dropped."""
    cidr = _env("VULTR_SSH_ALLOW_CIDR")
    if not cidr or "/" not in cidr or cidr.startswith("0.0.0.0"):
        raise VultrError("set VULTR_SSH_ALLOW_CIDR to the app VM's public IPv4, e.g. 203.0.113.7/32")
    subnet, size = cidr.split("/")
    groups = _api("GET", "/firewalls?per_page=500").get("firewall_groups", [])
    gid = next((g["id"] for g in groups if g.get("description") == FIREWALL_DESC), None)
    if gid is None:
        gid = _api("POST", "/firewalls", {"description": FIREWALL_DESC})["firewall_group"]["id"]
    rules = _api("GET", f"/firewalls/{gid}/rules?per_page=500").get("firewall_rules", [])
    want = (subnet, int(size))
    for r in rules:
        if (r.get("subnet"), int(r.get("subnet_size", -1))) != want or str(r.get("port")) != "22":
            _api("DELETE", f"/firewalls/{gid}/rules/{r['id']}")   # stale app IP or a hand-added rule
    if not any((r.get("subnet"), int(r.get("subnet_size", -1))) == want and str(r.get("port")) == "22"
               for r in rules):
        _api("POST", f"/firewalls/{gid}/rules", {
            "ip_type": "v4", "protocol": "tcp", "port": "22", "subnet": subnet,
            "subnet_size": int(size), "notes": "vulture app VM"})
    return gid


def _instance(iid: str) -> dict:
    return _api("GET", f"/instances/{iid}")["instance"]


def delete_instance(iid: str) -> None:
    for attempt in range(5):
        try:
            _api("DELETE", f"/instances/{iid}")
            return
        except VultrError as e:
            if "HTTP 404" in str(e):
                return
            if attempt == 4:
                raise
            time.sleep(3 * (attempt + 1))


def janitor_once(max_age_min: int = MAX_AGE_MIN) -> list[str]:
    """Delete vulture-scan instances older than max_age_min. Returns the ids deleted."""
    deleted, cursor = [], ""
    now = datetime.now(timezone.utc)
    while True:
        page = _api("GET", f"/instances?tag={TAG}&per_page=100" + (f"&cursor={cursor}" if cursor else ""))
        for inst in page.get("instances", []):
            if TAG not in (inst.get("tags") or []) and inst.get("tag") != TAG:
                continue  # belt and braces: never touch anything we didn't tag
            try:
                created = datetime.fromisoformat(inst["date_created"])
            except (KeyError, ValueError):
                continue
            if (now - created).total_seconds() > max_age_min * 60:
                delete_instance(inst["id"])
                deleted.append(inst["id"])
        cursor = ((page.get("meta") or {}).get("links") or {}).get("next") or ""
        if not cursor:
            return deleted


_janitor_started = False
_janitor_lock = threading.Lock()


def start_janitor(every_s: int = 600) -> None:
    global _janitor_started
    with _janitor_lock:
        if _janitor_started:
            return
        _janitor_started = True

    def loop():
        while True:
            try:
                gone = janitor_once()
                if gone:
                    print(f"vultr janitor: deleted orphaned scan VMs {gone}", flush=True)
            except Exception as e:  # keep running; the next pass retries
                print(f"vultr janitor: {e}", flush=True)
            time.sleep(every_s)

    threading.Thread(target=loop, daemon=True, name="vultr-janitor").start()


# --------------------------------------------------------------------------- keys + cloud-init

def _ed25519() -> tuple[str, str]:
    """(OpenSSH private key PEM, 'ssh-ed25519 AAAA...' public line)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                           serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                      serialization.PublicFormat.OpenSSH).decode()
    return priv, pub


def _indent(text: str, n: int) -> str:
    return "\n".join(" " * n + line for line in text.strip().splitlines())


def cloud_init(login_pub: str, host_priv: str, host_pub: str) -> str:
    return f"""#cloud-config
ssh_deletekeys: true
ssh_genkeytypes: []
ssh_keys:
  ed25519_private: |
{_indent(host_priv, 4)}
  ed25519_public: {host_pub}
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys:
      - {login_pub}
write_files:
  # Docker listens on the VM's loopback only; the app reaches it through the SSH tunnel.
  - path: /etc/systemd/system/docker.service.d/vulture.conf
    content: |
      [Service]
      ExecStart=
      ExecStart=/usr/bin/dockerd -H fd:// -H tcp://127.0.0.1:2375 --containerd=/run/containerd/containerd.sock
runcmd:
  # Containers never get to the cloud metadata service (it holds this user-data).
  - iptables -I FORWARD -d 169.254.169.254 -j DROP
  - command -v dockerd || (apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io)
  - systemctl daemon-reload && systemctl restart docker
  - iptables -I DOCKER-USER -d 169.254.169.254 -j DROP
  - touch /run/vulture-ready
"""


# --------------------------------------------------------------------------- SSH + Docker tunnel

class _Tunnel:
    """127.0.0.1:<random> on this side -> 127.0.0.1:2375 on the VM, over one pinned SSH session."""

    def __init__(self, host: str, login_priv: str, host_pub: str):
        import paramiko
        self._paramiko = paramiko
        key = paramiko.Ed25519Key.from_private_key(io.StringIO(login_priv))
        expected = paramiko.Ed25519Key(data=base64.b64decode(host_pub.split()[1]))
        self.ssh = paramiko.SSHClient()
        hk = host if SSH_PORT == 22 else f"[{host}]:{SSH_PORT}"
        self.ssh.get_host_keys().add(hk, "ssh-ed25519", expected)
        self.ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.ssh.connect(host, port=SSH_PORT, username="root", pkey=key, allow_agent=False, look_for_keys=False,
                         timeout=15, banner_timeout=15, auth_timeout=15)
        self.ssh.get_transport().set_keepalive(15)
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(16)
        self.port = self.srv.getsockname()[1]
        self._closed = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self._closed:
            try:
                conn, peer = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._pipe, args=(conn, peer), daemon=True).start()

    def _pipe(self, conn: socket.socket, peer):
        try:
            chan = self.ssh.get_transport().open_channel("direct-tcpip", ("127.0.0.1", 2375), peer)
        except Exception:
            conn.close()
            return
        try:
            while True:
                r, _, _ = select.select([conn, chan], [], [], 60)
                if conn in r:
                    data = conn.recv(65536)
                    if not data:
                        break
                    chan.sendall(data)
                if chan in r:
                    data = chan.recv(65536)
                    if not data:
                        break
                    conn.sendall(data)
        except OSError:
            pass
        finally:
            chan.close()
            conn.close()

    def run(self, cmd: str, timeout: int = 60) -> tuple[int, str]:
        _, out, err = self.ssh.exec_command(cmd, timeout=timeout)
        code = out.channel.recv_exit_status()
        return code, (out.read() + err.read()).decode(errors="replace")

    def close(self):
        self._closed = True
        with contextlib.suppress(Exception):
            self.srv.close()
        with contextlib.suppress(Exception):
            self.ssh.close()


def _connect(host: str, login_priv: str, host_pub: str, deadline: float) -> _Tunnel:
    last = None
    while time.time() < deadline:
        try:
            t = _Tunnel(host, login_priv, host_pub)
            code, _ = t.run("test -f /run/vulture-ready && docker info >/dev/null 2>&1", timeout=20)
            if code == 0:
                return t
            t.close()
        except Exception as e:  # sshd not up yet, cloud-init still running, ...
            last = e
        time.sleep(5)
    raise VultrError(f"scan VM didn't finish booting in {BOOT_TIMEOUT}s ({type(last).__name__ if last else 'cloud-init'})")


def _tar_dir(path: Path) -> io.BytesIO:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for f in sorted(path.iterdir()):
            if f.is_file():
                tf.add(f, arcname=f.name)
    buf.seek(0)
    return buf


def ensure_images(client, worker_image: str, sinkhole_image: str, emit: Emit) -> None:
    """Build the worker + sinkhole images on the VM unless a snapshot already has them."""
    import docker
    for tag, folder in ((worker_image, "worker"), (sinkhole_image, "sinkhole")):
        try:
            client.images.get(tag)
            continue
        except docker.errors.ImageNotFound:
            pass
        emit("fetch", f"vm: building {tag} on the scan VM", {"vm": {"event": "building", "image": tag}})
        client.images.build(fileobj=_tar_dir(IMAGES_DIR / folder), custom_context=True, tag=tag,
                            rm=True, forcerm=True, pull=True, timeout=900)


# The order matters: allow loopback + the established SSH session first, then drop the rest.
_LOCK_EGRESS = r"""set -e
IF=$(ip route show default | awk '{print $5; exit}')
iptables -I DOCKER-USER -o "$IF" -j DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -P OUTPUT DROP
ip6tables -P OUTPUT DROP || true
ip6tables -P FORWARD DROP || true
echo locked
"""


# --------------------------------------------------------------------------- the public entry point

@contextlib.contextmanager
def scan_vm(scan_id: str, emit: Emit) -> Iterator[tuple[object, Callable[[], None]]]:
    """Yields (docker_client, lock_egress) for a fresh VM, and always deletes the VM afterwards."""
    import docker
    start_janitor()
    if not _vm_slots.acquire(timeout=1800):
        raise VultrError(f"no free scan VM slot (VULTR_MAX_VMS={MAX_VMS})")
    iid = None
    tunnel = None
    client = None
    t0 = time.time()
    try:
        fw = _firewall_group()
        login_priv, login_pub = _ed25519()
        host_priv, host_pub = _ed25519()
        body = {
            "region": REGION, "plan": PLAN, "label": f"vulture-scan-{scan_id}", "hostname": f"scan-{scan_id}",
            "tags": [TAG], "firewall_group_id": fw, "backups": "disabled", "enable_ipv6": False,
            "user_data": base64.b64encode(cloud_init(login_pub, host_priv, host_pub).encode()).decode(),
        }
        body["snapshot_id" if SNAPSHOT_ID else "os_id"] = SNAPSHOT_ID or OS_ID
        iid = _api("POST", "/instances", body)["instance"]["id"]
        emit("fetch", f"vm: created Vultr instance in {REGION} ({PLAN})",
             {"vm": {"event": "created", "id": iid, "region": REGION, "plan": PLAN}})

        deadline = t0 + BOOT_TIMEOUT
        ip = ""
        while time.time() < deadline:
            inst = _instance(iid)
            ip = inst.get("main_ip") or ""
            if inst.get("status") == "active" and ip and ip != "0.0.0.0":
                break
            time.sleep(5)
        else:
            raise VultrError(f"Vultr instance not active after {BOOT_TIMEOUT}s")
        tunnel = _connect(ip, login_priv, host_pub, deadline)
        emit("fetch", f"vm: booted in {round(time.time() - t0)}s, Docker ready",
             {"vm": {"event": "booted", "id": iid, "seconds": round(time.time() - t0)}})

        client = docker.DockerClient(base_url=f"tcp://127.0.0.1:{tunnel.port}", timeout=900)

        def lock_egress():
            code, out = tunnel.run(_LOCK_EGRESS)
            if code != 0 or "locked" not in out:
                raise VultrError(f"couldn't cut outbound traffic on the scan VM: {out[-300:]}")
            emit("sandbox", "vm: outbound traffic blocked on the scan VM", {"vm": {"event": "egress_blocked"}})

        yield client, lock_egress
    finally:
        with contextlib.suppress(Exception):
            if client is not None:
                client.close()
        if tunnel is not None:
            tunnel.close()
        if iid:
            try:
                delete_instance(iid)
                emit("observe", f"vm: destroyed after {round(time.time() - t0)}s",
                     {"vm": {"event": "destroyed", "id": iid, "seconds": round(time.time() - t0)}})
            except Exception as e:
                # The janitor will get it; say so instead of failing a finished scan.
                emit("observe", f"vm: delete failed ({e}); the janitor will remove it",
                     {"vm": {"event": "delete_failed", "id": iid}})
        _vm_slots.release()
