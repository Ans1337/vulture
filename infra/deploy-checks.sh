#!/usr/bin/env bash
# Post-deploy health checks, run by deploy-main.sh from the commit it just deployed.
# Usage: infra/deploy-checks.sh [host:port]   (run from the repo root; reads APP_TOKEN from .env)
set -euo pipefail
BASE="http://${1:-127.0.0.1:8001}"

curl -fsS --retry 15 --retry-all-errors --retry-delay 1 --max-time 5 "$BASE/" | cmp dashboard/index.html -

# With APP_TOKEN in .env the API must answer 401 without it and 200 with it; without one it is open and must answer 200.
TOKEN=$(sed -n 's/^APP_TOKEN=//p' .env 2>/dev/null | tail -1)
AUTH=()
if [[ -n $TOKEN ]]; then
    [[ $(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "$BASE/api/limits") == 401 ]]
    AUTH=(-H "Authorization: Bearer $TOKEN")
else
    echo "NOTE: no APP_TOKEN in .env, the API is open to anyone who can reach it." >&2
fi
curl -fsS --max-time 5 -o /dev/null ${AUTH[@]+"${AUTH[@]}"} "$BASE/api/limits"

# Scans are private to the personal nonce that created them: no nonce lists nothing, a bad nonce is refused.
[[ $(curl -fsS --max-time 5 ${AUTH[@]+"${AUTH[@]}"} "$BASE/api/scans") == "[]" ]]
[[ $(curl -s --max-time 5 -o /dev/null -w '%{http_code}' ${AUTH[@]+"${AUTH[@]}"} -H "X-Vulture-Nonce: bad" "$BASE/api/scans") == 401 ]]
curl -fsS --max-time 5 -o /dev/null ${AUTH[@]+"${AUTH[@]}"} -X POST "$BASE/api/nonce"
echo "Health checks passed on $BASE"
