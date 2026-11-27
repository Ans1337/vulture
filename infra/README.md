# Deploying on a VM

Notes for running Vulture on a single Ubuntu VM (e.g. Vultr Cloud Compute). Not automated yet;
run the steps by hand. Use a VM dedicated to Vulture: scans run untrusted code on its kernel.

## 1. Install Docker

```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sudo sh     # Docker Engine + compose plugin
sudo usermod -aG docker "$USER" && newgrp docker
```

## 2. Clone and start

```bash
git clone <repo-url> vulture && cd vulture
./start.sh            # creates .env from .env.example; add VULTR_INFERENCE_API_KEY + AGENT_MODEL, then:
docker compose up -d api
```

The API has **no authentication** and is published on `127.0.0.1:8000` by default. Pick one:

- **Recommended: reverse proxy with basic auth + TLS.** Keep the default bind and put Caddy (or
  nginx) in front. Minimal `/etc/caddy/Caddyfile` (hash from `caddy hash-password`; Caddy older than
  2.8 spells the directive `basicauth`):

  ```
  vulture.example.com {
      basic_auth {
          judge <bcrypt-hash>
      }
      reverse_proxy 127.0.0.1:8000
  }
  ```

- **Open bind (only on a firewalled / throwaway VM):** `VULTURE_BIND=0.0.0.0 ./start.sh`, or put
  `VULTURE_BIND=0.0.0.0` in `.env`. Anyone who can reach port 8000 can start scans. Note that
  ports published by Docker bypass `ufw`.

## 3. Block cloud metadata from containers

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
