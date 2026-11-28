from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
sys.dont_write_bytecode = True
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
    ollama_project_profile,
    forget_key,
    read_key,
)

from getzilla.on_demand import ensure_components, find_installed_project


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['ollama']:
        local = argparse.ArgumentParser(prog='getzilla setup-agent ollama')
        local.add_argument('action', choices=('preview', 'apply', 'rollback'))
        local.add_argument('token', nargs='?', help='exact token from preview')
        args = local.parse_args(argv[1:])
        try:
            result = ollama_project_profile(Path.cwd(), args.action, args.token)
        except (ValueError, OSError, RecursionError, OverflowError) as exc:
            print(f'Local profile refused: {exc}', file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2))
        return 0

    parser = argparse.ArgumentParser(
        epilog='Local Qwen Code profile: getzilla setup-agent ollama preview',
        description=(
            'Configure a coding agent and its models. Inside an installed project, validate and add its '
            'adapter before changing user settings. Model keys stay in user configuration, never in the project.'
        ),
    )
    parser.add_argument('--agent', choices=AGENTS, default=DEFAULT_AGENT)
    parser.add_argument('--provider', choices=PROVIDERS, default=DEFAULT_PROVIDER)
    parser.add_argument('--model', help='OpenRouter model id (default depends on the agent)')
    parser.add_argument('--key-stdin', action='store_true', help='read the OpenRouter key from the first stdin line')
    parser.add_argument('--forget-key', action='store_true', help='remove stored user key variables and exit')
    args = parser.parse_args(argv)
    if args.forget_key:
        for item in forget_key(Path.home()).written:
            print(f'removed: {item}')
        return 0

    try:
        project = find_installed_project(Path.cwd())
        if project is not None:
            for added in ensure_components(project, [f'agent:{args.agent}'], source=ROOT):
                print(f'project: recorded {added.component}; added {len(added.files)} files; kept {len(added.kept)} custom files')
    except (ValueError, OSError) as exc:
        print(f'ERROR: project phase failed: {exc}', file=sys.stderr)
        return 2

    try:
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
        result = configure(args.agent, args.provider, Path.home(), key=key, model=args.model)
    except (ValueError, OSError) as exc:
        phase = 'project phase completed; ' if project is not None else ''
        print(f'ERROR: {phase}global configuration failed: {exc}', file=sys.stderr)
        return 2
    for item in result.written:
        print(f'configured: {item}')
    for step in result.next_steps:
        print(f'next: {step}')
    print(f'agent setup: {result.status}')
    return 0 if result.status == 'configured' else 3


if __name__ == '__main__':
    raise SystemExit(main())
