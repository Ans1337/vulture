#!/usr/bin/env bash
# Build the sandbox images and start Vulture on http://127.0.0.1:8000 (VULTURE_BIND overrides the address)
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || { cp .env.example .env; echo "Created .env from .env.example (add your keys there)."; }
bash samples/fake-malware/build.sh   # fake-stealer.tgz, injection.tgz, hang.tgz
docker compose --profile build build worker sinkhole
docker compose up --build -d api docker-proxy
# Same lookup order as compose: shell env, then .env, then the 127.0.0.1 default.
BIND="${VULTURE_BIND:-$(sed -n 's/^VULTURE_BIND=//p' .env 2>/dev/null | tail -1)}"
BIND="${BIND:-127.0.0.1}"
HOST="$BIND"; [ "$HOST" = "0.0.0.0" ] && HOST="<this-machine-ip>"
echo "Vulture is running: http://$HOST:8000 (bound to $BIND)"
[ "$BIND" = "127.0.0.1" ] || echo "WARNING: the API has no authentication and is reachable on $BIND:8000."
