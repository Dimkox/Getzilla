#!/usr/bin/env bash
# Getzilla installer for Linux and macOS.
#
#   download this script from a release tag, check its SHA-256 against the digest
#   published in README.md / QUICKSTART.md, then run it (never pipe it into a shell)
#
# Bootstraps Git/Python/curl, then resolves current managed software, downloads
# Getzilla, reports provider setup and runs the final health check. Nothing is
# changed in your projects unless you ask for it with one of the variables below.
#
# Coding agent (asked when a terminal is attached, otherwise Qwen Code):
#   qwen    Qwen Code    (npm @qwen-code/qwen-code, needs Node.js 20+)
#   codex   Codex CLI    (npm @openai/codex, needs Node.js 20+)
#   claude  Claude Code  (official versioned manifest and verified native binary)
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
# data (OSV CVE database, current verified OpenGrep) and current release-bound
# Superpowers, BMAD and Spec Kit payloads for your coding agent. There is no option to skip it:
# if any part does not install, the installer stops with an error and says what to fix.
# Selected managed software is resolved and verified each run. The updater is
# also available as an explicit command after installation.
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
    say "Selected $agent; exact current software is installed after source setup."
  fi

  fetch_getzilla "$repo" "$ref" "$home"
  link_getzilla_command "$home"
  setup_python_env "$home" "$python"
  python="$home/.venv/bin/python"
  export PATH="$home/.venv/bin:$PATH"
  [ -x "$python" ] || fail "Getzilla's managed Python environment is missing."
  install_agent "$home" "$python" "$agent"

  local agent_status=0
  if [ "${GETZILLA_SKIP_AGENT:-0}" != "1" ]; then
    configure_agent "$home" "$python" "$agent" "$provider" || agent_status=$?
  fi

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

  say "Checking this machine after all updates..."
  local final=(--verify-only --home "$home")
  [ "${GETZILLA_SKIP_AGENT:-0}" = "1" ] || final+=(--agent "$agent")
  local selected=() tool
  IFS=',' read -r -a selected <<< "${GETZILLA_TOOLS:-}"
  for tool in "${selected[@]}"; do [ -z "$tool" ] || final+=(--tool "$tool"); done
  "$python" "$home/scripts/getzilla_install_managed.py" "${final[@]}" </dev/null \
    || fail "Actual managed software/PATH changed or latest metadata is unavailable."
  local doctor_status=0
  (cd "$home" && "$python" scripts/getzilla_doctor.py --offer-install) || doctor_status=$?
  if [ "$doctor_status" -eq 0 ] && [ "$agent_status" -eq 0 ]; then
    printf '\nGetzilla is ready in %s\n' "$home"
  else
    printf '\nGetzilla installation is incomplete in %s: health=%s, agent/provider=%s. Follow the errors and next steps above.\n' "$home" "$doctor_status" "$agent_status"
    return 3
  fi
  # Optional notification runs only after every mandatory stage and final check.
  "$python" "$home/scripts/getzilla_install_analytics.py" --ready </dev/null >/dev/null 2>&1 || true
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

# Current managed Node archives use exact official hashes. Old distribution
# Node packages cannot replace the resolved runtime.





install_agent() {
  local home="$1" python="$2" agent="$3" tool
  local arguments=(--home "$home")
  [ "${GETZILLA_SKIP_AGENT:-0}" = "1" ] || arguments+=(--agent "$agent")
  local selected=()
  IFS=',' read -r -a selected <<< "${GETZILLA_TOOLS:-}"
  for tool in "${selected[@]}"; do [ -z "$tool" ] || arguments+=(--tool "$tool"); done
  "$python" "$home/scripts/getzilla_install_managed.py" "${arguments[@]}" </dev/null \
    || fail "Current selected managed software is incomplete; see exact target/path/error above."
  export PATH="${GETZILLA_STATE_HOME:-$HOME/.getzilla}/bin:$PATH"
  hash -r
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
    printf '%s\n' "$key" | (cd "$home" && "$python" scripts/getzilla_setup_agent.py "${args[@]}" --key-stdin)
  else
    (cd "$home" && env -u OPENROUTER_API_KEY -u GEMINI_API_KEY -u COPILOT_GITHUB_TOKEN "$python" scripts/getzilla_setup_agent.py "${args[@]}" </dev/null)
  fi
}

update_security_data() {
  # Not optional: without vulnerability data the gates would scan against an empty CVE
  # database, so a failure stops the install instead of warning.
  local home="$1" python="$2"
  say "Updating vulnerability data (OSV CVE database) and current verified OpenGrep..."
  (cd "$home" && "$python" scripts/getzilla_update.py --only osv --only opengrep) \
    || fail "Vulnerability data did not install (FAIL lines above). Fix the network or the error and run this installer again (or: cd \"$home\" && $python scripts/getzilla_update.py --only osv --only opengrep)."
}

install_workflow_baseline() {
  # Not optional: current release-bound source and supported closed data payloads.
  # No ambient workflow installer or vendor code runs during materialization.
  local home="$1" python="$2" venv_python
  node_ok 20 || fail "Node.js 20 or newer is required by the managed profile and is unavailable."
  venv_python="$home/.venv/bin/python"
  [ -x "$venv_python" ] || fail "Getzilla's Python environment ($home/.venv) is missing; it is needed by the workflow source/data adapter."
  say "Resolving the current verified workflow baseline (Superpowers, BMAD, Spec Kit)..."
  (cd "$home" && PATH="$home/.venv/bin:$PATH" "$python" scripts/getzilla_update.py --only baseline) \
    || fail "The workflow baseline did not install (FAIL lines above). Fix it and run this installer again (or: cd \"$home\" && $python scripts/getzilla_update.py --only baseline)."

}

setup_python_env() {
  local home="$1" python="$2"
  say "Resolving current test/quality tools and verifying their complete wheel closure..."
  "$python" "$home/scripts/getzilla_install_managed.py" --environment-only --home "$home" </dev/null \
    || fail "Current managed Python environment is incomplete; no historical pins were used."
}

link_getzilla_command() {
  # One `getzilla <command>` for every tool, next to the agent CLIs in ~/.local/bin.
  local home="$1"
  mkdir -p "$HOME/.local/bin"
  local command="$HOME/.local/bin/getzilla"
  if [ -e "$command" ] || [ -L "$command" ]; then
    [ -L "$command" ] && [ "$(readlink "$command")" = "$home/bin/getzilla" ] \
      || fail "User command conflict: $command; existing bytes preserved."
  else
    ln -s "$home/bin/getzilla" "$command"
  fi
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
