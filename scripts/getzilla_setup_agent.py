from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.agent_setup import (
    AGENT_KEY_ENV,
    AGENTS,
    DEFAULT_AGENT,
    DEFAULT_PROVIDER,
    KEY_ENV,
    NATIVE_ONLY,
    PROVIDERS,
    configure,
    forget_key,
    read_key,
)

parser = argparse.ArgumentParser(
    description=(
        'Point a coding agent (Qwen Code, Codex, Claude Code, Gemini CLI, Copilot CLI or Grok Build) at its models. '
        'With --provider openrouter the OpenRouter key is read from OPENROUTER_API_KEY, from stdin '
        'with --key-stdin, or asked for. It is kept as a user environment variable (OPENROUTER_API_KEY) that every '
        'agent reads, never in a project. Gemini CLI and Copilot CLI use their own accounts; an optional '
        'GEMINI_API_KEY or COPILOT_GITHUB_TOKEN is kept the same way.'
    ),
)
parser.add_argument('--agent', choices=AGENTS, default=DEFAULT_AGENT)
parser.add_argument('--provider', choices=PROVIDERS, default=DEFAULT_PROVIDER)
parser.add_argument('--model', help='OpenRouter model id (default depends on the agent)')
parser.add_argument('--key-stdin', action='store_true', help='read the OpenRouter key from the first stdin line')
parser.add_argument('--forget-key', action='store_true', help='remove the stored OpenRouter key variables and exit')
args = parser.parse_args()

if args.forget_key:
    for item in forget_key(Path.home()).written:
        print(f'removed: {item}')
    raise SystemExit(0)

key_env = AGENT_KEY_ENV.get(args.agent, KEY_ENV)
wants_key = (args.agent not in NATIVE_ONLY and args.provider == 'openrouter') or args.agent in AGENT_KEY_ENV
key = None
if wants_key:
    if args.key_stdin:
        key = read_key()
    else:
        key = os.environ.get(key_env) or None
        if key is None and sys.stdin.isatty():
            hint = 'https://openrouter.ai/keys' if key_env == KEY_ENV else 'optional'
            key = getpass.getpass(f'{key_env} ({hint}, Enter to skip): ').strip() or None

try:
    result = configure(args.agent, args.provider, Path.home(), key=key, model=args.model)
except ValueError as exc:
    print(f'ERROR: {exc}', file=sys.stderr)
    raise SystemExit(2) from None
for item in result.written:
    print(f'configured: {item}')
for step in result.next_steps:
    print(f'next: {step}')
