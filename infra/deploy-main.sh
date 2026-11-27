#!/usr/bin/env bash
set -euo pipefail

# Installed as a forced SSH command on the production VM.
if [[ ! ${SSH_ORIGINAL_COMMAND:-} =~ ^[0-9a-f]{40}$ ]]; then
    echo "Expected the commit SHA from a push to main." >&2
    exit 1
fi

cd /opt/vulture-main
exec 9>/run/lock/vulture-deploy.lock
flock 9
git fetch --no-tags origin refs/heads/main
if [[ $(git rev-parse FETCH_HEAD) != "$SSH_ORIGINAL_COMMAND" ]]; then
    echo "A different commit is now on main. Skipping this deployment."
    exit 0
fi

git switch --detach "$SSH_ORIGINAL_COMMAND"
export COMPOSE_PROJECT_NAME=vulture
export VULTURE_API_BIND=127.0.0.1:8001
docker compose --profile build build api worker sinkhole
docker compose up -d --no-build docker-proxy api

curl -fsS --retry 15 --retry-all-errors --retry-delay 1 --max-time 5 \
    http://127.0.0.1:8001/ | cmp dashboard/index.html -
# With APP_TOKEN in .env the API must answer 401 without it and 200 with it; without one it is open and must answer 200.
TOKEN=$(grep '^APP_TOKEN=' .env | cut -d= -f2)
if [[ -n $TOKEN ]]; then
    [[ $(curl -s --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:8001/api/scans) == 401 ]]
    curl -fsS --max-time 5 -o /dev/null -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8001/api/scans
else
    echo "NOTE: no APP_TOKEN in .env, the API is open to anyone who can reach it." >&2
    curl -fsS --max-time 5 -o /dev/null http://127.0.0.1:8001/api/scans
fi
echo "Deployed $SSH_ORIGINAL_COMMAND to parivant.se"
