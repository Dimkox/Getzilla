#!/usr/bin/env bash
# Getzilla installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/Dimkox/Getzilla/main/scripts/install.sh | bash
#
# Installs what is missing (Git, Python 3.10+, curl, your coding agent), downloads
# Getzilla, points the agent at its models and runs the health check. Nothing is
# changed in your projects unless you ask for it with one of the variables below.
#
# Coding agent (asked when a terminal is attached, otherwise Qwen Code):
#   qwen    Qwen Code    (npm @qwen-code/qwen-code, needs Node.js 20+)
#   codex   Codex CLI    (npm @openai/codex, needs Node.js 20+)
#   claude  Claude Code  (official installer from claude.ai)
#   grok    Grok Build   (official installer from x.ai, xAI account only)
# Models come from OpenRouter with your own key (https://openrouter.ai/keys) unless
# you pick the agent's own sign-in. The key is stored only in your user settings.
#
# Optional environment variables:
#   GETZILLA_HOME         where Getzilla is kept (default: ~/Getzilla)
#   GETZILLA_REF          branch or tag to install (default: main)
#   GETZILLA_REPO         Git URL to install from (default: the GitHub repository)
#   GETZILLA_PROJECT      existing project: print the read-only install plan for it
#   GETZILLA_NEW_PROJECT  absent path: create a new project with Getzilla in it (Linux)
#   GETZILLA_AGENT        qwen | codex | claude | grok (default: ask, else qwen)
#   GETZILLA_PROVIDER     openrouter | native (default: ask, else openrouter)
#   GETZILLA_MODEL        OpenRouter model id for Qwen Code or Codex
#   OPENROUTER_API_KEY    your OpenRouter key (otherwise asked for, never echoed)
#   GETZILLA_SKIP_AGENT=1 do not install or configure the coding agent
#   GETZILLA_SKIP_GROK=1  do not install the Grok Build CLI (when the agent is grok)
#   GETZILLA_NONINTERACTIVE=1  never ask; use the defaults above
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

  local agent provider
  agent="$(choose_agent)"
  provider="$(choose_provider "$agent")"
  say "Coding agent: $agent (models: $provider)"
  if [ "${GETZILLA_SKIP_AGENT:-0}" = "1" ]; then
    say "Skipping the coding agent (GETZILLA_SKIP_AGENT=1)."
  else
    install_agent "$agent"
  fi

  fetch_getzilla "$repo" "$ref" "$home"

  if [ "${GETZILLA_SKIP_AGENT:-0}" != "1" ]; then
    configure_agent "$home" "$python" "$agent" "$provider"
  fi

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
  2. In your project run: $(agent_command "$agent")
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

can_ask() {
  [ "${GETZILLA_NONINTERACTIVE:-0}" != "1" ] && { true </dev/tty; } 2>/dev/null
}

ask() {
  local prompt="$1" default="$2" answer=""
  if can_ask; then
    printf '%s' "$prompt" >/dev/tty
    IFS= read -r answer </dev/tty || answer=""
  fi
  printf '%s' "${answer:-$default}"
}

choose_agent() {
  local agent="${GETZILLA_AGENT:-}"
  if [ -z "$agent" ]; then
    case "$(ask $'Coding agent: 1) Qwen Code  2) Codex  3) Claude Code  4) Grok Build  [1]: ' 1)" in
      2|codex) agent=codex ;;
      3|claude) agent=claude ;;
      4|grok) agent=grok ;;
      *) agent=qwen ;;
    esac
  fi
  case "$agent" in
    qwen|codex|claude|grok) printf '%s' "$agent" ;;
    *) fail "GETZILLA_AGENT must be qwen, codex, claude or grok (got '$agent')." ;;
  esac
}

choose_provider() {
  local agent="$1" provider="${GETZILLA_PROVIDER:-}"
  if [ "$agent" = "grok" ]; then
    printf 'native'
    return 0
  fi
  if [ -z "$provider" ]; then
    case "$(ask $'Models: 1) OpenRouter with your own key  2) the agent\'s own sign-in  [1]: ' 1)" in
      2|native) provider=native ;;
      *) provider=openrouter ;;
    esac
  fi
  case "$provider" in
    openrouter|native) printf '%s' "$provider" ;;
    *) fail "GETZILLA_PROVIDER must be openrouter or native (got '$provider')." ;;
  esac
}

agent_command() {
  case "$1" in
    qwen) printf 'qwen' ;;
    codex) printf 'codex   (trust the project when asked)' ;;
    claude) printf 'claude   (trust the project folder when asked)' ;;
    grok) printf 'grok   (first time: sign in, then type /hooks-trust)' ;;
  esac
}

node_ok() {
  have node && node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' >/dev/null 2>&1
}

ensure_node() {
  node_ok && return 0
  say "Installing Node.js (20 or newer is needed)..."
  if [ "$(uname -s)" = "Darwin" ] && have brew; then
    brew install node || true
  elif have apt-get; then
    as_root apt-get install -y nodejs npm </dev/null || true
  elif have dnf; then
    as_root dnf install -y nodejs npm </dev/null || true
  elif have pacman; then
    as_root pacman -Sy --noconfirm nodejs npm </dev/null || true
  elif have zypper; then
    as_root zypper --non-interactive install nodejs npm </dev/null || true
  elif have apk; then
    as_root apk add --no-cache nodejs npm </dev/null || true
  fi
  hash -r
  node_ok && return 0
  say "Node.js 20 or newer is still missing. Install it from https://nodejs.org and run this installer again."
  return 1
}

npm_global() {
  local package="$1"
  if npm install -g "$package" </dev/null >/dev/null 2>&1; then
    return 0
  fi
  mkdir -p "$HOME/.local/bin"
  if npm install -g --prefix "$HOME/.local" "$package" </dev/null >/dev/null 2>&1; then
    export PATH="$HOME/.local/bin:$PATH"
    hash -r
    say "Installed $package into ~/.local; add ~/.local/bin to PATH if '$2' is not found."
    return 0
  fi
  return 1
}

install_agent() {
  case "$1" in
    qwen) install_npm_agent qwen @qwen-code/qwen-code@latest "Qwen Code" ;;
    codex) install_npm_agent codex @openai/codex@latest "Codex CLI" ;;
    claude) ensure_claude ;;
    grok)
      if [ "${GETZILLA_SKIP_GROK:-0}" = "1" ]; then
        say "Skipping the Grok Build CLI (GETZILLA_SKIP_GROK=1)."
      else
        ensure_grok
      fi
      ;;
  esac
}

install_npm_agent() {
  local command="$1" package="$2" label="$3"
  if have "$command"; then
    say "$label: already installed."
    return 0
  fi
  ensure_node || return 0
  say "Installing $label..."
  if npm_global "$package" "$command"; then
    say "$label installed."
  else
    say "Could not install $label now. Later run: npm install -g $package"
  fi
}

ensure_claude() {
  if have claude; then
    say "Claude Code: already installed."
    return 0
  fi
  say "Installing Claude Code..."
  local script
  script="$(mktemp)"
  if curl -fsSL https://claude.ai/install.sh -o "$script" && bash "$script" </dev/null >/dev/null 2>&1; then
    rm -f "$script"
    export PATH="$HOME/.local/bin:$PATH"
    hash -r
    say "Claude Code installed."
  else
    rm -f "$script"
    say "Could not install Claude Code now. Later run: curl -fsSL https://claude.ai/install.sh | bash"
  fi
}

configure_agent() {
  local home="$1" python="$2" agent="$3" provider="$4" key="${OPENROUTER_API_KEY:-}"
  local args=(--agent "$agent" --provider "$provider")
  [ -n "${GETZILLA_MODEL:-}" ] && args+=(--model "$GETZILLA_MODEL")
  if [ "$provider" = "openrouter" ] && [ "$agent" != "grok" ] && [ -z "$key" ] && can_ask; then
    printf 'OpenRouter API key (create one at https://openrouter.ai/keys, Enter to skip): ' >/dev/tty
    IFS= read -rs key </dev/tty || key=""
    printf '\n' >/dev/tty
  fi
  say "Configuring $agent..."
  if [ -n "$key" ]; then
    printf '%s\n' "$key" | (cd "$home" && "$python" scripts/getzilla_setup_agent.py "${args[@]}" --key-stdin) \
      || say "Agent configuration failed (see the message above); run it again later with scripts/getzilla_setup_agent.py."
  else
    (cd "$home" && OPENROUTER_API_KEY= "$python" scripts/getzilla_setup_agent.py "${args[@]}" </dev/null) || true
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
