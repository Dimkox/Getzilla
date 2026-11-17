#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
output="${GETZILLA_LIVE_OUTPUT:-$root/.getzilla/runtime/live/trust-ci-$(date +%s)-$$}"
exec python3 "$root/scripts/getzilla_live.py" --root "$root" --cell trust-ci --output "$output" --timeout-seconds 1200
