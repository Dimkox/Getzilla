#!/usr/bin/env bash
# Getzilla installer for Linux and macOS.
#
#   download this script from a release tag, check its SHA-256 against the digest
#   published in README.md / QUICKSTART.md, then run it (never pipe it into a shell)
#
# Installs what is missing (Git, Python 3.10+, curl, your coding agent), downloads
# Getzilla, points the agent at its models and runs the health check. Nothing is
# changed in your projects unless you ask for it with one of the variables below.
#
# Coding agent (asked when a terminal is attached, otherwise Qwen Code):
#   qwen    Qwen Code    (npm @qwen-code/qwen-code, needs Node.js 20+)
#   codex   Codex CLI    (npm @openai/codex, needs Node.js 20+)
#   claude  Claude Code  (official installer from claude.ai)
#   gemini  Gemini CLI   (npm @google/gemini-cli, Google account or GEMINI_API_KEY)
#   copilot Copilot CLI  (npm @github/copilot, needs Node.js 22+, GitHub Copilot account)
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
#   GETZILLA_AGENT        qwen | codex | claude | gemini | copilot | grok (default: ask, else qwen)
#   GEMINI_API_KEY        optional Gemini key; COPILOT_GITHUB_TOKEN optional Copilot token
#   GETZILLA_PROVIDER     openrouter | native (default: ask, else openrouter)
#   GETZILLA_MODEL        OpenRouter model id for Qwen Code or Codex
#   OPENROUTER_API_KEY    your OpenRouter key (otherwise asked for, never echoed)
#   GETZILLA_SKIP_AGENT=1 do not install or configure the coding agent
#   GETZILLA_SKIP_GROK=1  do not install the Grok Build CLI (when the agent is grok)
#   GETZILLA_EU_AI_ACT=1|0     turn the optional EU AI Act checks on or off without asking
#   GETZILLA_NONINTERACTIVE=1  never ask; use the defaults above
#
# Every run (first install or re-run) installs the mandatory baseline: the vulnerability
# data (OSV CVE database, pinned OpenGrep scanner) and the pinned, commit-verified
# Superpowers, BMAD and Spec Kit for your coding agent. There is no option to skip it:
# if any part does not install, the installer stops with an error and says what to fix.
# Updating third-party tools to newer versions stays a separate command:
# scripts/getzilla_update.py --only agents --only sources.
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
  local compliance
  compliance="$(choose_eu_ai_act)"
  if [ -n "$compliance" ]; then say "EU AI Act checks: on (getzilla components add compliance:eu-ai-act)"; fi
  if [ "${GETZILLA_SKIP_AGENT:-0}" = "1" ]; then
    say "Skipping the coding agent (GETZILLA_SKIP_AGENT=1)."
  else
    install_agent "$agent"
  fi

  fetch_getzilla "$repo" "$ref" "$home"
  link_getzilla_command "$home"
  setup_python_env "$home" "$python"

  if [ "${GETZILLA_SKIP_AGENT:-0}" != "1" ]; then
    configure_agent "$home" "$python" "$agent" "$provider"
  fi

  say "Checking this machine..."
  local doctor_status=0
  (cd "$home" && "$python" scripts/getzilla_doctor.py --offer-install) || doctor_status=$?

  update_security_data "$home" "$python"
  install_workflow_baseline "$home" "$python"

  if [ -n "${GETZILLA_NEW_PROJECT:-}" ]; then
    say "Creating a new project at $GETZILLA_NEW_PROJECT ..."
    (cd "$home" && "$python" scripts/install_into.py --materialize-new "$GETZILLA_NEW_PROJECT" --agents "$agent" \
      ${compliance:+--compliance "$compliance"})
    say "Connecting the baseline (Superpowers, BMAD, Spec Kit) to the new project..."
    (cd "$home" && PATH="$home/.venv/bin:$PATH" "$python" scripts/getzilla_baseline.py apply \
      --project "$GETZILLA_NEW_PROJECT" --agent "$agent") \
      || fail "The baseline was not connected to $GETZILLA_NEW_PROJECT (FAIL lines above). Fix it and run: cd \"$home\" && $python scripts/getzilla_baseline.py apply --project \"$GETZILLA_NEW_PROJECT\" --agent $agent"
  elif [ -n "${GETZILLA_PROJECT:-}" ]; then
    say "Install plan for $GETZILLA_PROJECT (read-only, nothing is written):"
    (cd "$home" && "$python" scripts/install_into.py --plan "$GETZILLA_PROJECT" ${compliance:+--compliance "$compliance"})
    if [ -n "$compliance" ]; then say "To turn on EU AI Act checks there: cd \"$GETZILLA_PROJECT\" && getzilla components add compliance:eu-ai-act"; fi
  fi

  if [ "$doctor_status" -eq 0 ]; then
    printf '\nGetzilla is ready in %s\n' "$home"
  else
    printf '\nGetzilla is installed in %s, but the health check reported problems (FAIL lines above).\n' "$home"
  fi
  cat <<EOF

Next:
  0. Every Getzilla tool is one command: getzilla help
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
    case "$(ask $'Coding agent: 1) Qwen Code  2) Codex  3) Claude Code  4) Gemini CLI  5) Copilot CLI  6) Grok Build  [1]: ' 1)" in
      2|codex) agent=codex ;;
      3|claude) agent=claude ;;
      4|gemini) agent=gemini ;;
      5|copilot) agent=copilot ;;
      6|grok) agent=grok ;;
      *) agent=qwen ;;
    esac
  fi
  case "$agent" in
    qwen|codex|claude|gemini|copilot|grok) printf '%s' "$agent" ;;
    *) fail "GETZILLA_AGENT must be qwen, codex, claude, gemini, copilot or grok (got '$agent')." ;;
  esac
}

# Offline hints only: the system time zone or locale of an EU member state. Nothing is looked up
# on the network and the IP address is never used.
eu_hint() {
  local zone="${TZ:-}" locale="${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}"
  if [ -z "$zone" ] && [ -L /etc/localtime ]; then
    zone="$(readlink /etc/localtime 2>/dev/null | sed -n 's#.*zoneinfo/##p')"
  fi
  if [ -z "$zone" ] && [ -r /etc/timezone ]; then
    zone="$(head -n1 /etc/timezone 2>/dev/null)"
  fi
  case "$zone" in
    Europe/Amsterdam|Europe/Athens|Europe/Berlin|Europe/Bratislava|Europe/Brussels|Europe/Bucharest|\
    Europe/Budapest|Europe/Busingen|Europe/Copenhagen|Europe/Dublin|Europe/Helsinki|Europe/Lisbon|\
    Europe/Ljubljana|Europe/Luxembourg|Europe/Madrid|Europe/Malta|Europe/Mariehamn|Europe/Nicosia|\
    Europe/Paris|Europe/Prague|Europe/Riga|Europe/Rome|Europe/Sofia|Europe/Stockholm|Europe/Tallinn|\
    Europe/Vienna|Europe/Vilnius|Europe/Warsaw|Europe/Zagreb|Atlantic/Canary|Atlantic/Madeira|\
    Atlantic/Azores|Asia/Nicosia|Asia/Famagusta) return 0 ;;
  esac
  case "$locale" in
    *_AT*|*_BE*|*_BG*|*_HR*|*_CY*|*_CZ*|*_DK*|*_EE*|*_FI*|*_FR*|*_DE*|*_GR*|*_HU*|*_IE*|*_IT*|\
    *_LV*|*_LT*|*_LU*|*_MT*|*_NL*|*_PL*|*_PT*|*_RO*|*_SK*|*_SI*|*_ES*|*_SE*) return 0 ;;
  esac
  return 1
}

# Prints "eu-ai-act" when the optional checks are turned on, nothing otherwise. Default: off.
choose_eu_ai_act() {
  case "${GETZILLA_EU_AI_ACT:-}" in
    1|yes|true|on) printf 'eu-ai-act'; return 0 ;;
    0|no|false|off) return 0 ;;
  esac
  eu_hint || return 0
  case "$(ask $'Does your project have users in the EU? Turn on EU AI Act checks (optional, can be added later) [y/N]: ' n)" in
    y|Y|yes|Yes|YES|д|Д|да|Да) printf 'eu-ai-act' ;;
  esac
}

choose_provider() {
  local agent="$1" provider="${GETZILLA_PROVIDER:-}"
  if [ "$agent" = "grok" ] || [ "$agent" = "gemini" ] || [ "$agent" = "copilot" ]; then
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
    gemini) printf 'gemini   (trust the folder when asked)' ;;
    copilot) printf 'copilot   (first time: /login, and trust the folder)' ;;
    grok) printf 'grok   (first time: sign in, then type /hooks-trust)' ;;
  esac
}

node_ok() {
  have node && node -e "process.exit(Number(process.versions.node.split('.')[0]) >= ${1:-20} ? 0 : 1)" >/dev/null 2>&1
}

# Pinned official Node.js archives with their published SHA-256 (nodejs.org SHASUMS256.txt).
# Distribution packages are often too old (Ubuntu 24.04 ships Node.js 18) and pull in hundreds
# of node-* packages; the archive installs for the current user without root.
node_archive() {
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64|Linux-amd64) echo "node-v24.20.0-linux-x64.tar.gz 855d581f8a4eb1a8117e3426de25fe02770592febcfb31369aee1ffbfee9e8ec" ;;
    Linux-aarch64|Linux-arm64) echo "node-v24.20.0-linux-arm64.tar.gz 3515603e2487879a39bc75716f1a2affd027500c64ba50e845cf72cb33219013" ;;
    Darwin-x86_64) echo "node-v24.20.0-darwin-x64.tar.gz 9e5b2644cf107befb6aefca676b96d3296bc10138096f022ed378d6233ed81f4" ;;
    Darwin-arm64) echo "node-v24.20.0-darwin-arm64.tar.gz 40e5607e5ecb3db9192723776da2d75d966260fc74a7a9e731c1bd67dda96bc8" ;;
  esac
}

checksum_ok() {
  if have sha256sum; then
    echo "$2  $1" | sha256sum -c - >/dev/null 2>&1
  else
    echo "$2  $1" | shasum -a 256 -c - >/dev/null 2>&1
  fi
}

install_node_archive() {
  local spec name digest version dir tmp
  spec="$(node_archive)"
  [ -n "$spec" ] && have curl || return 1
  name="${spec% *}"
  digest="${spec#* }"
  version="${name#node-v}"
  version="${version%%-*}"
  tmp="$(mktemp -d)"
  if ! curl -fsSL "https://nodejs.org/dist/v$version/$name" -o "$tmp/$name" || ! checksum_ok "$tmp/$name" "$digest"; then
    rm -rf "$tmp"
    say "Node.js $version download failed or did not match its published SHA-256."
    return 1
  fi
  dir="$HOME/.local/lib/nodejs"
  mkdir -p "$dir" "$HOME/.local/bin"
  rm -rf "$dir/${name%.tar.gz}"
  tar -xzf "$tmp/$name" -C "$dir"
  rm -rf "$tmp"
  for tool in node npm npx; do
    ln -sf "$dir/${name%.tar.gz}/bin/$tool" "$HOME/.local/bin/$tool"
  done
  export PATH="$HOME/.local/bin:$PATH"
  hash -r
  # Global npm packages (the agent CLIs) then land next to it in ~/.local/bin, without root.
  npm config set prefix "$HOME/.local" >/dev/null 2>&1 || true
}

ensure_node() {
  local minimum="${1:-20}"
  node_ok "$minimum" && return 0
  say "Installing Node.js ($minimum or newer is needed)..."
  if [ "$(uname -s)" = "Darwin" ] && have brew; then
    brew install node || true
  else
    install_node_archive || true
  fi
  hash -r
  node_ok "$minimum" && return 0
  # Distribution packages only as a fallback.
  if have apt-get; then
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
  node_ok "$minimum" && return 0
  say "Node.js $minimum or newer is still missing. Install it from https://nodejs.org and run this installer again."
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
    gemini) install_npm_agent gemini @google/gemini-cli@latest "Gemini CLI" ;;
    copilot) install_npm_agent copilot @github/copilot@latest "Copilot CLI" 22 ;;
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
  local command="$1" package="$2" label="$3" node_minimum="${4:-20}"
  if have "$command"; then
    say "$label: already installed."
    return 0
  fi
  ensure_node "$node_minimum" || return 0
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
  local home="$1" python="$2" agent="$3" provider="$4" key_name="" prompt="" key=""
  case "$agent" in
    gemini) key_name=GEMINI_API_KEY; prompt='Gemini API key (optional, Enter to sign in with Google instead): ' ;;
    copilot) key_name=COPILOT_GITHUB_TOKEN; prompt='GitHub token for Copilot (optional, Enter to use /login instead): ' ;;
    grok) ;;
    *)
      if [ "$provider" = "openrouter" ]; then
        key_name=OPENROUTER_API_KEY
        prompt='OpenRouter API key (create one at https://openrouter.ai/keys, Enter to skip): '
      fi
      ;;
  esac
  [ -n "$key_name" ] && key="${!key_name:-}"
  local args=(--agent "$agent" --provider "$provider")
  [ -n "${GETZILLA_MODEL:-}" ] && args+=(--model "$GETZILLA_MODEL")
  if [ -n "$key_name" ] && [ -z "$key" ] && can_ask; then
    printf '%s' "$prompt" >/dev/tty
    IFS= read -rs key </dev/tty || key=""
    printf '\n' >/dev/tty
  fi
  say "Configuring $agent..."
  if [ -n "$key" ]; then
    printf '%s\n' "$key" | (cd "$home" && "$python" scripts/getzilla_setup_agent.py "${args[@]}" --key-stdin) \
      || say "Agent configuration failed (see the message above); run it again later with scripts/getzilla_setup_agent.py."
  else
    (cd "$home" && env -u OPENROUTER_API_KEY -u GEMINI_API_KEY -u COPILOT_GITHUB_TOKEN "$python" scripts/getzilla_setup_agent.py "${args[@]}" </dev/null) || true
  fi
}

update_security_data() {
  # Not optional: without vulnerability data the gates would scan against an empty CVE
  # database, so a failure stops the install instead of warning.
  local home="$1" python="$2"
  say "Updating vulnerability data (OSV CVE database) and the pinned OpenGrep scanner..."
  (cd "$home" && "$python" scripts/getzilla_update.py --only osv --only opengrep) \
    || fail "Vulnerability data did not install (FAIL lines above). Fix the network or the error and run this installer again (or: cd \"$home\" && $python scripts/getzilla_update.py --only osv --only opengrep)."
}

install_workflow_baseline() {
  # Not optional: Superpowers, BMAD and Spec Kit at the pinned, commit-verified versions.
  # BMAD runs on Node.js; Spec Kit installs through uv, which brings its own Python 3.11+.
  local home="$1" python="$2" venv_python
  ensure_node 20 || true
  node_ok 20 || fail "Node.js 20 or newer is required for the BMAD installer and could not be installed."
  venv_python="$home/.venv/bin/python"
  [ -x "$venv_python" ] || fail "Getzilla's Python environment ($home/.venv) is missing; it is needed for the Spec Kit installer."
  if ! { have uv && uv --version 2>/dev/null | grep -q '^uv 0\.11\.12\b'; }; then
    "$venv_python" -m pip install --disable-pip-version-check --quiet "uv==0.11.12" </dev/null \
      || fail "Installing uv 0.11.12 (needed for the pinned Spec Kit CLI) failed."
  fi
  say "Installing the pinned workflow baseline (Superpowers, BMAD, Spec Kit)..."
  (cd "$home" && PATH="$home/.venv/bin:$PATH" "$python" scripts/getzilla_update.py --only baseline) \
    || fail "The workflow baseline did not install (FAIL lines above). Fix it and run this installer again (or: cd \"$home\" && $python scripts/getzilla_update.py --only baseline)."
}

setup_python_env() {
  # Getzilla's own environment with the pinned test and quality tools (PEP 668 safe).
  local home="$1" python="$2"
  say "Creating Getzilla's Python environment with the pinned test and quality tools..."
  if "$python" -m venv "$home/.venv" </dev/null \
    && "$home/.venv/bin/python" -m pip install --disable-pip-version-check -q \
      -r "$home/.getzilla/config/python-test-requirements.txt" \
      -r "$home/.getzilla/config/python-quality-requirements.txt" </dev/null; then
    say "Python environment: $home/.venv"
  else
    printf 'WARNING: could not create %s/.venv; verify will report missing coverage, ruff and bandit.\n' "$home" >&2
  fi
}

link_getzilla_command() {
  # One `getzilla <command>` for every tool, next to the agent CLIs in ~/.local/bin.
  local home="$1"
  mkdir -p "$HOME/.local/bin"
  ln -sf "$home/bin/getzilla" "$HOME/.local/bin/getzilla"
  say "getzilla command: $HOME/.local/bin/getzilla (add ~/.local/bin to PATH if it is not found)"
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
