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

# The health checks live in the checked-out commit, so changing them doesn't need this script reinstalled.
bash infra/deploy-checks.sh 127.0.0.1:8001
echo "Deployed $SSH_ORIGINAL_COMMAND to parivant.se"
