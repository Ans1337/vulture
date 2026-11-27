#!/usr/bin/env bash
# Build the sandbox images and start Vulture on http://127.0.0.1:8000 (VULTURE_API_BIND=host:port overrides it)
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || { cp .env.example .env; echo "Created .env from .env.example (add your keys there)."; }
bash samples/fake-malware/build.sh   # fake-stealer.tgz, injection.tgz, hang.tgz
docker compose --profile build build worker sinkhole
docker compose up --build -d api docker-proxy
# Same lookup order as compose: shell env, then .env, then the 127.0.0.1:8000 default.
BIND="${VULTURE_API_BIND:-$(sed -n 's/^VULTURE_API_BIND=//p' .env 2>/dev/null | tail -1)}"
BIND="${BIND:-127.0.0.1:8000}"
case "$BIND" in *:*) ;; *) BIND="0.0.0.0:$BIND" ;; esac   # a bare port binds all interfaces
echo "Vulture is running: http://${BIND/0.0.0.0/localhost} (bound to $BIND)"
case "$BIND" in 127.0.0.1:*) ;; *) echo "WARNING: the API has no authentication and is reachable on $BIND." ;; esac
