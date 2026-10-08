#!/usr/bin/env bash
# Getzilla installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/Dimkox/Getzilla/main/scripts/install.sh | bash
#
# Installs what is missing (Git, Python 3.10+, curl, Grok Build CLI), downloads
# Getzilla and runs its health check. Nothing is changed in your projects unless
# you ask for it with one of the variables below.
#
# Optional environment variables:
#   GETZILLA_HOME         where Getzilla is kept (default: ~/Getzilla)
#   GETZILLA_REF          branch or tag to install (default: main)
#   GETZILLA_REPO         Git URL to install from (default: the GitHub repository)
#   GETZILLA_PROJECT      existing project: print the read-only install plan for it
#   GETZILLA_NEW_PROJECT  absent path: create a new project with Getzilla in it (Linux)
#   GETZILLA_SKIP_GROK=1  do not install the Grok Build CLI
#
# Everything runs inside main(), so a partially downloaded script does nothing.

main() {
  set -euo pipefail

  local home="${GETZILLA_HOME:-$HOME/Getzilla}"
  local ref="${GETZILLA_REF:-main}"
  local repo="${GETZILLA_REPO:-https://github.com/Dimkox/Getzilla.git}"
  local os
  os="$(uname -s)"

  say "Getzilla installer ($os)"

  ensure_git_and_python "$os"
  local python
  python="$(find_python)" || fail "Python 3.10 or newer is still missing. Install it and run this installer again."
  say "Python: $("$python" --version 2>&1)"
  say "Git: $(git --version)"

  if [ "${GETZILLA_SKIP_GROK:-0}" = "1" ]; then
    say "Skipping the Grok Build CLI (GETZILLA_SKIP_GROK=1)."
  else
    ensure_grok
  fi

  fetch_getzilla "$repo" "$ref" "$home"

  say "Checking this machine..."
  local doctor_status=0
  (cd "$home" && "$python" scripts/getzilla_doctor.py --offer-install) || doctor_status=$?

  if [ -n "${GETZILLA_NEW_PROJECT:-}" ]; then
    say "Creating a new project at $GETZILLA_NEW_PROJECT ..."
    (cd "$home" && "$python" scripts/install_into.py --materialize-new "$GETZILLA_NEW_PROJECT")
  elif [ -n "${GETZILLA_PROJECT:-}" ]; then
    say "Install plan for $GETZILLA_PROJECT (read-only, nothing is written):"
    (cd "$home" && "$python" scripts/install_into.py --plan "$GETZILLA_PROJECT")
  fi

  if [ "$doctor_status" -eq 0 ]; then
    printf '\nGetzilla is ready in %s\n' "$home"
  else
    printf '\nGetzilla is installed in %s, but the health check reported problems (FAIL lines above).\n' "$home"
  fi
  cat <<EOF

Next:
  1. New project:      cd "$home" && $python scripts/install_into.py --materialize-new /path/to/new/project
     Existing project: cd "$home" && $python scripts/install_into.py --plan /path/to/your/project
  2. In your project run: grok   (first time: sign in, then type /hooks-trust)
  3. Vibe-code the feature, then run /getzilla-delivery and
     $python scripts/getzilla_verify.py --mode pr
EOF
}

say() { printf '==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

as_root() {
  if [ "$(id -u)" = "0" ]; then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    fail "Need administrator rights to run: $* (install sudo or run as root)."
  fi
}

python_ok() {
  "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
}

find_python() {
  local candidate
  for candidate in python3 python3.13 python3.12 python3.11 python3.10 python; do
    if have "$candidate" && python_ok "$candidate"; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

ensure_git_and_python() {
  local os="$1" need=()
  have git || need+=(git)
  find_python >/dev/null || need+=(python)
  have curl || need+=(curl)
  [ "${#need[@]}" -eq 0 ] && return 0
  say "Installing: ${need[*]}"

  if [ "$os" = "Darwin" ]; then
    if have brew; then
      local pkgs=()
      for item in "${need[@]}"; do
        case "$item" in python) pkgs+=(python@3.13) ;; *) pkgs+=("$item") ;; esac
      done
      brew install "${pkgs[@]}"
    else
      xcode-select --install >/dev/null 2>&1 || true
      fail "macOS asked to install the Command Line Tools (Git and Python). Finish that, then run this installer again."
    fi
  elif have apt-get; then
    as_root apt-get update -y </dev/null
    as_root apt-get install -y git python3 python3-venv curl ca-certificates </dev/null
  elif have dnf; then
    as_root dnf install -y git python3 curl </dev/null
  elif have yum; then
    as_root yum install -y git python3 curl </dev/null
  elif have pacman; then
    as_root pacman -Sy --noconfirm git python curl </dev/null
  elif have zypper; then
    as_root zypper --non-interactive install git python3 curl </dev/null
  elif have apk; then
    as_root apk add --no-cache git python3 curl bash </dev/null
  else
    fail "Unknown package manager. Install ${need[*]} yourself and run this installer again."
  fi
  hash -r
}

ensure_grok() {
  if have grok; then
    say "Grok Build CLI: already installed."
    return 0
  fi
  say "Installing the Grok Build CLI..."
  local script
  script="$(mktemp)"
  if curl -fsSL https://x.ai/cli/install.sh -o "$script" \
    && bash "$script" </dev/null 2>&1 | tr '\r' '\n' | { grep -Ev '^[[:space:]]*$|^[[:space:]#=>-]*[0-9]{1,3}(\.[0-9]+)?[[:space:]]*%' || true; }; then
    rm -f "$script"
    export PATH="$HOME/.local/bin:$HOME/.grok/bin:$PATH"
    hash -r
    if have grok; then
      say "Grok Build CLI installed."
    else
      say "Grok Build CLI installed. Open a new terminal before running 'grok'."
    fi
  else
    rm -f "$script"
    say "Could not install the Grok Build CLI now. Later run: curl -fsSL https://x.ai/cli/install.sh | bash"
  fi
}

fetch_getzilla() {
  local repo="$1" ref="$2" home="$3"
  if [ -d "$home/.git" ]; then
    say "Updating Getzilla in $home"
    git -C "$home" fetch --depth 1 origin "$ref"
    git -C "$home" checkout -q --detach FETCH_HEAD
  elif [ -e "$home" ]; then
    fail "$home exists and is not a Getzilla checkout. Set GETZILLA_HOME to another folder."
  else
    say "Downloading Getzilla to $home"
    git clone -q --depth 1 --branch "$ref" "$repo" "$home"
  fi
}

main "$@"
