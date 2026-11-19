#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
if [[ -n "${GETZILLA_LIVE_BINDING:-}" ]]; then
  exec python3 "$root/scripts/getzilla_live.py" --root "$root" --cell trust-ci \
    --output "$GETZILLA_LIVE_ARTIFACTS" --worker
fi
compose_file="$root/trust-ci/compose.test.yaml"
project_name="adaptive-trust-ci-pgtest-${USER:-ci}-$$"

cleanup() {
  docker compose \
    --project-name "$project_name" \
    -f "$compose_file" \
    down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup

docker compose \
  --project-name "$project_name" \
  -f "$compose_file" \
  up \
  --build \
  --abort-on-container-exit \
  --exit-code-from postgres-integration \
  postgres-integration
