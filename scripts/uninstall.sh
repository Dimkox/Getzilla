#!/usr/bin/env bash
# Getzilla uninstaller for Linux and macOS: the reverse of scripts/install.sh.
#
#   bash ~/Getzilla/scripts/uninstall.sh            show the plan and ask
#   bash ~/Getzilla/scripts/uninstall.sh --dry-run  show the plan only
#   bash ~/Getzilla/scripts/uninstall.sh --yes      do not ask
#
# Same as `getzilla self-uninstall`. See `--help` for the --keep-* options.
# Your projects, system Git/Python/Node.js and vendor-installed agents are not changed.

main() {
  set -euo pipefail
  local here home python=""
  here="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  home="${GETZILLA_HOME:-$(dirname -- "$here")}"
  local core="$home/scripts/getzilla_self_uninstall.py"
  [ -f "$core" ] || { printf 'ERROR: %s not found. Set GETZILLA_HOME to the Getzilla folder.\n' "$core" >&2; exit 2; }
  for candidate in "$home/.venv/bin/python" python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 \
      && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
      python="$candidate"
      break
    fi
  done
  [ -n "$python" ] || { printf 'ERROR: Python 3.10 or newer is required.\n' >&2; exit 2; }
  # Python reads the whole script before it runs, so it can remove its own folder.
  exec "$python" "$core" --home "$home" "$@"
}

main "$@"
