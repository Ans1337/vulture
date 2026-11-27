"""Part 5: a throwaway Vultr instance per scan (SANDBOX_MODE=vultr).

Real malware never touches the app VM: each scan gets a fresh instance, the orchestrator drives that
instance's Docker daemon over SSH (same code path as local mode), and the instance is DELETED afterwards.

Env:
  VULTR_API_KEY            required
  VULTR_SSH_KEY_ID         id of an SSH key registered at Vultr (its private half is VULTR_SSH_KEY_FILE)
  VULTR_SSH_KEY_FILE       path to that private key inside the API container (default /run/secrets/vultr_ssh_key)
  VULTR_REGION             default ewr
  VULTR_PLAN               default vc2-2c-4gb
  VULTR_OS_ID              default 2284 (Ubuntu 24.04 x64), ignored when a snapshot is used
  VULTR_SNAPSHOT_ID        optional pre-baked snapshot (Docker + images already built): boots in ~1 min, not ~4
  VULTR_FIREWALL_GROUP_ID  optional firewall group: allow inbound 22 from the app VM only
  VULTR_REPO_URL           repo cloned by cloud-init to build the images when no snapshot is used
  VULTR_BOOT_TIMEOUT       seconds to wait for the VM to be usable (default 600)
  VULTR_VM_MAX_AGE         janitor: destroy tagged instances older than this (default 3600)
"""
from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import time
import urllib.error
import urllib.request
from typing import Callable

log = logging.getLogger("vulture.vultr")
API = "https://api.vultr.com/v2"
TAG = "vulture-scan"


class VultrError(Exception):
    pass


def _cfg(name: str, default: str = "") -> str:
    return os.environ.get(name, "").strip() or default


class Vultr:
    """Tiny REST client. `transport` is injectable so tests never touch the network."""

    def __init__(self, key: str | None = None, transport: Callable | None = None):
        self.key = key or _cfg("VULTR_API_KEY")
        if not self.key:
            raise VultrError("VULTR_API_KEY is not set")
        self._t = transport or self._http

    def _http(self, method: str, path: str, body: dict | None) -> tuple[int, dict]:
        req = urllib.request.Request(API + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}

    def call(self, method: str, path: str, body: dict | None = None, ok=(200, 201, 202, 204)) -> dict:
        status, data = self._t(method, path, body)
        if status not in ok:
            raise VultrError(f"Vultr API {method} {path} -> {status}: {str(data.get('error', ''))[:200]}")
        return data

    # --- instances ---
    def create_instance(self, scan_id: str, user_data: str) -> dict:
        body = {
            "region": _cfg("VULTR_REGION", "ewr"), "plan": _cfg("VULTR_PLAN", "vc2-2c-4gb"),
            "label": f"vulture-{scan_id}", "hostname": f"vulture-{scan_id}",
            "tags": [TAG, f"scan-{scan_id}"], "backups": "disabled", "enable_ipv6": False,
            "user_data": base64.b64encode(user_data.encode()).decode(),
        }
        if _cfg("VULTR_SNAPSHOT_ID"):
            body["snapshot_id"] = _cfg("VULTR_SNAPSHOT_ID")
        else:
            body["os_id"] = int(_cfg("VULTR_OS_ID", "2284"))
        if _cfg("VULTR_SSH_KEY_ID"):
            body["sshkey_id"] = [_cfg("VULTR_SSH_KEY_ID")]
        if _cfg("VULTR_FIREWALL_GROUP_ID"):
            body["firewall_group_id"] = _cfg("VULTR_FIREWALL_GROUP_ID")
        return self.call("POST", "/instances", body)["instance"]

    def get_instance(self, instance_id: str) -> dict | None:
        status, data = self._t("GET", f"/instances/{instance_id}", None)
        if status == 404:
            return None
        if status != 200:
            raise VultrError(f"Vultr API GET instance -> {status}")
        return data["instance"]

    def delete_instance(self, instance_id: str) -> None:
        status, _ = self._t("DELETE", f"/instances/{instance_id}", None)
        if status not in (200, 202, 204, 404):
            raise VultrError(f"Vultr API DELETE instance -> {status}")

    def list_tagged(self) -> list[dict]:
        out, cursor = [], ""
        while True:
            data = self.call("GET", f"/instances?tag={TAG}&per_page=100" + (f"&cursor={cursor}" if cursor else ""))
            out += data.get("instances", [])
            cursor = (data.get("meta", {}).get("links", {}) or {}).get("next") or ""
            if not cursor:
                return out


def cloud_init() -> str:
    """Runs on first boot. With a snapshot the images already exist and this is a no-op."""
    repo = _cfg("VULTR_REPO_URL", "https://github.com/Ans1337/vulture")
    return f"""#!/bin/bash
set -eux
if ! docker image inspect vulture-worker:latest >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y docker.io git
  systemctl enable --now docker
  git clone --depth 1 {repo} /opt/vulture
  docker build -t vulture-worker:latest /opt/vulture/sandbox-images/worker
  docker build -t vulture-sinkhole:latest /opt/vulture/sandbox-images/sinkhole
fi
touch /var/lib/vulture-ready
"""


def _ssh(ip: str, command: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh", "-i", _cfg("VULTR_SSH_KEY_FILE", "/run/secrets/vultr_ssh_key"), "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=8",
         f"root@{ip}", command], capture_output=True, timeout=timeout)


class Sandbox:
    """Context manager: create the VM, wait until it's usable, hand out a Docker client, ALWAYS destroy it."""

    def __init__(self, scan_id: str, emit, cancel=None, api: Vultr | None = None, ssh=_ssh, sleep=time.sleep):
        self.scan_id, self.emit, self.cancel = scan_id, emit, cancel
        self.api, self.ssh, self.sleep = api or Vultr(), ssh, sleep
        self.instance_id: str | None = None
        self.ip: str | None = None
        self.report: dict = {}

    def __enter__(self):
        t0 = time.time()
        self.emit("sandbox", "creating throwaway Vultr instance", {"vm": "creating"})
        try:
            inst = self.api.create_instance(self.scan_id, cloud_init())
            self.instance_id = inst["id"]
            self.emit("sandbox", f"VM created ({self.instance_id[:8]}), waiting for it to boot", {"vm": "created"})
            deadline = t0 + int(_cfg("VULTR_BOOT_TIMEOUT", "600"))
            while True:
                if self.cancel is not None and self.cancel.is_set():
                    raise InterruptedError("cancelled")
                if time.time() > deadline:
                    raise TimeoutError("the sandbox VM did not become ready in time")
                i = self.api.get_instance(self.instance_id)
                if i and i.get("status") == "active" and i.get("main_ip", "0.0.0.0") != "0.0.0.0":
                    self.ip = i["main_ip"]
                    if self.ssh(self.ip, "test -f /var/lib/vulture-ready && docker info >/dev/null 2>&1").returncode == 0:
                        break
                self.sleep(5)
            self.emit("sandbox", f"VM booted and ready in {round(time.time() - t0)}s", {"vm": "ready"})
            import docker
            return docker.DockerClient(base_url=f"ssh://root@{self.ip}", use_ssh_client=True, timeout=120)
        except BaseException:
            self.destroy()          # a half-built VM must never be left billing
            raise

    def destroy(self) -> dict:
        """Delete the instance and verify with the API that it's gone."""
        if self.instance_id is None:
            return self.report
        gone, err = False, None
        for attempt in range(4):
            try:
                self.api.delete_instance(self.instance_id)
                gone = self.api.get_instance(self.instance_id) is None
                if gone:
                    break
            except Exception as e:
                err = str(e)
            self.sleep(2 * (attempt + 1))
        self.report = {"vm_id": self.instance_id, "destroyed": gone, **({"error": err} if err and not gone else {})}
        self.emit("destroy", "Vultr VM destroyed" if gone else "FAILED to destroy the Vultr VM (janitor will retry)",
                  {"vm": "destroyed" if gone else "destroy_failed", "vm_report": self.report})
        self.instance_id = None
        return self.report

    def __exit__(self, *exc):
        self.destroy()
        return False


def janitor(api: Vultr, live_scan_ids: set[str], max_age: int, now: float | None = None) -> int:
    """Destroy tagged instances that belong to no live scan and are older than max_age seconds."""
    from datetime import datetime, timezone
    now = now or time.time()
    n = 0
    for i in api.list_tagged():
        scan = next((t[5:] for t in i.get("tags", []) if t.startswith("scan-")), None)
        try:
            age = now - datetime.fromisoformat(i["date_created"].replace("Z", "+00:00")).timestamp()
        except Exception:
            age = max_age + 1
        if scan in live_scan_ids or age < max_age:
            continue
        try:
            api.delete_instance(i["id"]); n += 1
            log.warning("janitor destroyed orphan VM %s (scan %s, %ds old)", i["id"], scan, age)
        except Exception:
            log.exception("janitor failed on %s", i["id"])
    return n
