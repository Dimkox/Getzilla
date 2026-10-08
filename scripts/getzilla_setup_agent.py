from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.agent_setup import AGENTS, DEFAULT_AGENT, DEFAULT_PROVIDER, KEY_ENV, PROVIDERS, configure, read_key

parser = argparse.ArgumentParser(
    description=(
        'Point a coding agent (Qwen Code, Codex, Claude Code or Grok Build) at its models. '
        'With --provider openrouter the OpenRouter key is read from OPENROUTER_API_KEY, from stdin '
        'with --key-stdin, or asked for; it is stored only in your user configuration, never in a project.'
    ),
)
parser.add_argument('--agent', choices=AGENTS, default=DEFAULT_AGENT)
parser.add_argument('--provider', choices=PROVIDERS, default=DEFAULT_PROVIDER)
parser.add_argument('--model', help='OpenRouter model id (default depends on the agent)')
parser.add_argument('--key-stdin', action='store_true', help='read the OpenRouter key from the first stdin line')
args = parser.parse_args()

key = None
if args.agent != 'grok' and args.provider == 'openrouter':
    if args.key_stdin:
        key = read_key()
    else:
        key = os.environ.get(KEY_ENV) or None
        if key is None and sys.stdin.isatty():
            key = getpass.getpass('OpenRouter API key (https://openrouter.ai/keys, Enter to skip): ').strip() or None

try:
    result = configure(args.agent, args.provider, Path.home(), key=key, model=args.model)
except ValueError as exc:
    print(f'ERROR: {exc}', file=sys.stderr)
    raise SystemExit(2) from None
for item in result.written:
    print(f'configured: {item}')
for step in result.next_steps:
    print(f'next: {step}')
