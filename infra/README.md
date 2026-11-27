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
