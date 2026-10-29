"""CLI for the optional Entire adapter. All results, including refusals, are explicit JSON."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .client import EntireClient, EntireError
from .operations import EntireAdapter


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd(), help='project Git root (default: current directory)')
    parser.add_argument('--context', help='explicit saved Entire context; no implicit login')
    parser.add_argument('--timeout', type=float, default=30, help='per-process wall limit in seconds, at most 300')
    parser.add_argument('--json', action='store_true', help='JSON is also the default output format')
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('status', help='validate tools, authentication and exact origin identity')
    clone = commands.add_parser('clone', help='clone an explicit Entire URL without checkout or submodules')
    clone.add_argument('url')
    clone.add_argument('target', type=Path)
    fetch = commands.add_parser('fetch', help='fetch one branch without tags or submodules')
    fetch.add_argument('branch')
    push = commands.add_parser('push', help='push one getzilla/ task branch with an exact production grant')
    push.add_argument('branch')
    push.add_argument('--head', required=True)
    push.add_argument('--request-id', required=True)
    trails = commands.add_parser('trails', help='list, show or explicitly create a project Trail')
    trail_commands = trails.add_subparsers(dest='trail_command', required=True)
    trail_commands.add_parser('list')
    show = trail_commands.add_parser('show')
    show.add_argument('trail_id')
    create = trail_commands.add_parser('create', help='link an already-published exact branch; never pushes')
    create.add_argument('--branch', required=True)
    create.add_argument('--base', required=True)
    create.add_argument('--title', required=True)
    create.add_argument('--body', default='')
    create.add_argument('--head', required=True)
    create.add_argument('--request-id', required=True)
    for name, help_text in [('checks', 'inspect provider gates without granting merge authority'),
                            ('merge', 'explicit unsupported result until external CI provenance is implemented')]:
        command = commands.add_parser(name, help=help_text)
        command.add_argument('trail_id')
        command.add_argument('--head', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'merge':
            raise EntireError('unsupported', 'Entire automated merge is unsupported; a trusted external CI adapter '
                              'bound to this repository, Trail and exact commit is required')
        if not args.context:
            raise EntireError('context', 'choose an explicit saved context with --context NAME')
        if not 0 < args.timeout <= 300:
            raise EntireError('timeout_limit', '--timeout must be greater than zero and at most 300 seconds')
        if os.name != 'posix':
            raise EntireError('unsupported_os', 'Entire remote operations currently require POSIX process-group cleanup')
        root = args.root.resolve(strict=True)
        client = EntireClient(root, context=args.context, timeout=args.timeout)
        adapter = EntireAdapter(root, client)
        if args.command == 'status':
            result = adapter.status()
        elif args.command == 'clone':
            result = adapter.clone(args.url, args.target)
        elif args.command == 'fetch':
            result = adapter.fetch(args.branch)
        elif args.command == 'push':
            result = adapter.push(args.branch, args.head, args.request_id)
        elif args.command == 'checks':
            result = adapter.checks(args.trail_id, args.head)
        elif args.trail_command in {'list', 'show'}:
            result = adapter.trails(getattr(args, 'trail_id', None))
        else:
            result = adapter.create_trail(args.branch, args.base, args.title, args.body, args.head, args.request_id)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except EntireError as exc:
        print(json.dumps({'status': 'blocked', 'code': exc.code, 'message': str(exc)}))
        return 130 if exc.code == 'cancelled' else 2
    except (OSError, ValueError):
        print(json.dumps({'status': 'blocked', 'code': 'local_error', 'message': 'local input or runtime state is unavailable'}))
        return 2
    except KeyboardInterrupt:
        print(json.dumps({'status': 'blocked', 'code': 'cancelled', 'message': 'cancelled; reconcile any started write before retrying'}))
        return 130
