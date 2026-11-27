#!/usr/bin/env bash
# Build the sandbox images and start Vulture on http://localhost:8000
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || { cp .env.example .env; echo "Created .env from .env.example (add your keys there)."; }
( cd samples/fake-malware && COPYFILE_DISABLE=1 tar czf fake-stealer.tgz fake-stealer )
docker compose --profile build build worker sinkhole
docker compose up --build -d api docker-proxy
echo "Vulture is running: http://localhost:8000"
