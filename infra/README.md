# Deploy parivant.se from GitHub

Pull requests into `main` and pushes to `main` build Vulture on a fresh GitHub runner
and check the dashboard and API. After those checks pass on a push to `main`, the deployment
job connects to the Ubuntu VM over SSH. The VM fetches the
tested commit, rebuilds the images, updates the `vulture` Compose project, and checks both
endpoints on `127.0.0.1:8001`. Caddy already forwards `parivant.se` to this address.

## One-time setup

1. Get the app and workflow onto GitHub's `main` branch together. The original app was
   developed on `mvp`. If the first deployment runs before setup is complete, you can
   re-run its failed job after step 4.

2. In the existing root SSH session on the VM, create a clean deployment checkout. These
   commands assume the current app lives in `/root/vulture`, with its production settings
   in `/root/vulture/.env`. The existing clone must be able to fetch from GitHub.

   ```bash
   cd /root/vulture
   git fetch origin refs/heads/main
   git worktree add --detach /opt/vulture-main FETCH_HEAD
   ln -s /root/vulture/.env /opt/vulture-main/.env
   install -m 0755 /opt/vulture-main/infra/deploy-main.sh /usr/local/sbin/vulture-deploy
   ```

   The separate checkout preserves the edits made when first setting up the VM.
   If the forced-command script changes later, reinstall it with the same `install` command.

3. On your laptop, create a key dedicated to this workflow and authorize it on the VM.
   The key can trigger the installed deployment command. Your existing SSH login still works.

   ```bash
   ssh-keygen -t ed25519 -N '' -C github-vulture-deploy -f ~/.ssh/vulture-actions
   sed 's|^|restrict,command="/usr/local/sbin/vulture-deploy" |' ~/.ssh/vulture-actions.pub |
     ssh root@parivant.se 'umask 077; mkdir -p /root/.ssh; cat >> /root/.ssh/authorized_keys'
   ```

4. Under **GitHub → Settings → Secrets and variables → Actions**, add two repository secrets.

   | Secret | Value |
   | --- | --- |
   | `VULTURE_DEPLOY_KEY` | The complete contents of `~/.ssh/vulture-actions` on your laptop, including the private key header and footer |
   | `VULTURE_KNOWN_HOSTS` | The public host-key line printed by the command below in your trusted VM session |

   ```bash
   awk '{ print "parivant.se", $1, $2 }' /etc/ssh/ssh_host_ed25519_key.pub
   ```

   SSH on port 22 must be reachable from the deployment runner. If the firewall restricts
   SSH source IPs, use a runner with an allowed source address.

## Check a deployment

Open **GitHub → Actions → Deploy parivant.se** for the build checks and the deployed commit.
A successful run verifies the served dashboard matches the checked-out HTML and the scan
API responds. Recreating the API clears in-memory scan history and interrupts active scans.
After the first deployment, use `/opt/vulture-main` for the deployed source, and keep editing
production secrets in `/root/vulture/.env`.

## Hardening: the API has no authentication

The API is published on `127.0.0.1` only (`VULTURE_API_BIND`, default `127.0.0.1:8000`; the
deployment uses `127.0.0.1:8001`). Keep it behind the reverse proxy (Caddy) and add auth there,
e.g. `basic_auth`. Do not bind it to `0.0.0.0`: ports published by Docker bypass `ufw`.

## Hardening: block cloud metadata from containers

The fetch container has normal network access (npm registry, GitHub). On a cloud VM that includes
the metadata service at `169.254.169.254`. Drop traffic from Docker bridges to it in the
`DOCKER-USER` chain (Docker leaves this chain to the admin):

```bash
sudo iptables -I DOCKER-USER -i docker0 -d 169.254.169.254 -j DROP
sudo iptables -I DOCKER-USER -i br-+ -d 169.254.169.254 -j DROP    # compose / per-scan networks
```

Check: `sudo iptables -L DOCKER-USER -n -v`. The rules are not persistent; re-add them after a reboot
(or save them with `iptables-persistent`). The detonation network is `internal` and has no route out
anyway; this rule is for the fetch stage.

## Not covered yet

- Throwaway Vultr instance per scan (today: throwaway containers per scan on this VM).
- Restricting the docker-proxy: `POST` + `CONTAINERS` is host-root equivalent for whoever controls
  the API. Keep the API behind auth.

## Throwaway Vultr VM per scan (`SANDBOX_MODE=vultr`)

With `SANDBOX_MODE=vultr` in `.env`, every scan runs on its own Vultr instance instead of on this
server (`api/vultr_vm.py`). `SANDBOX_MODE=docker`, the default, keeps the local containers.

1. my.vultr.com → **Account → API**: enable the API and, under **Access Control**, allow only this
   server's IPv4 (`/32`). Put the key in `/root/vulture/.env` as `VULTR_API_KEY=`.
2. Set `VULTR_SSH_ALLOW_CIDR=<this server's IPv4>/32` and `SANDBOX_MODE=vultr`, then redeploy.

Per scan the app creates a `vc2-2c-4gb` instance in `sto`, tagged `vulture-scan`, in the
firewall group `vulture-scan: ssh from app VM only` (created on first use; inbound TCP 22 from
`VULTR_SSH_ALLOW_CIDR` only). The SSH login key and the SSH host key are generated per scan and
passed in through cloud-init, so the connection is pinned. Cloud-init installs Docker listening on
the VM's loopback only, and the app drives it through the SSH tunnel: it builds the worker and
sinkhole images, runs the fetch stage, blocks all outbound traffic on the VM with iptables
(Vultr firewalls only filter inbound), runs the sandbox and detonation, and then deletes the
instance. A janitor deletes `vulture-scan` instances older than `VULTR_MAX_AGE_MIN` (default 60),
and `VULTR_MAX_VMS` (default 3) caps how many run at once.

A cold VM takes about 3–5 minutes before the scan starts (boot, Docker, image build). To speed it
up, run one scan, snapshot a VM with Docker and both images built, and set `VULTR_SNAPSHOT_ID`.
