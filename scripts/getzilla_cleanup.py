#!/usr/bin/env python3
"""What Getzilla leaves on disk, and guarded removal of worktrees that hold no unique work.

  getzilla cleanup inventory [--json] [--temp DIR]
  getzilla cleanup worktrees [--json] [--remove]
  getzilla cleanup snapshot <commit> | snapshot --remove <path>

`inventory` classes: protected (state, receipts, evidence, worktrees), ephemeral (reproducible
output) and unknown (never deleted without an owner record). It deletes nothing.
`worktrees` lists every Git worktree with the reasons it must stay. Only with --remove does it
remove the ones under .getzilla/runtime/worktrees that keep no changes, no unique ignored files
and no commits missing from remote-tracking refs. Branches are never deleted.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.resource_inventory import inventory  # noqa: E402
from getzilla.util import find_root  # noqa: E402
from getzilla import review_snapshot  # noqa: E402
from getzilla.worktree_safety import WorktreeError, plan, remove  # noqa: E402


def _size(value: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if value < 1024 or unit == 'GB':
            return f'{value:.0f} {unit}' if unit == 'B' else f'{value:.1f} {unit}'
        value /= 1024
    return f'{value} B'  # pragma: no cover


def _inventory(args: argparse.Namespace) -> int:
    report = inventory(find_root(), Path(args.temp) if args.temp else None)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    print(f'Getzilla resources: {len(report["resources"])} (nothing deleted)')
    for name in ('protected', 'ephemeral', 'unknown'):
        group = report['totals'].get(name, {'resources': 0, 'bytes': 0})
        print(f'  {name:<10} {group["resources"]:>5} resource(s) {_size(group["bytes"]):>10}')
    for item in report['resources']:
        flag = '' if item['complete'] else ' (size incomplete)'
        print(f'  {item["class"]:<10} {item["location"]:<8} {item["name"]} {_size(item["bytes"])}{flag}')
    for place, usage in sorted(report['disk'].items()):
        if usage:
            print(f'Disk {place}: {_size(usage["free"])} free of {_size(usage["total"])}')
    copies = report['repository_copies']
    if copies:
        total = sum(item['bytes'] for item in copies)
        print(f'Repository copies (review snapshots and the like, kept until you decide): '
              f'{len(copies)}, {_size(total)}')
        for item in sorted(copies, key=lambda entry: -entry['bytes'])[:10]:
            print(f'  {_size(item["bytes"]):>10}  {item["path"]}')
        if len(copies) > 10:
            print(f'  ... {len(copies) - 10} more; use --json for all.')
    if not report['complete']:
        print('Some sizes are incomplete: unreadable entries or the entry budget was reached.')
    return 0


def _worktrees(args: argparse.Namespace) -> int:
    root = find_root()
    try:
        report = plan(root)
        if args.remove:
            report['results'] = [remove(root, item['path']) for item in report['worktrees'] if item['removable']]
    except WorktreeError as exc:
        print(f'getzilla cleanup: {exc}', file=sys.stderr)
        return 2
    failed = int(any(result['result'] == 'error' for result in report.get('results', [])))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return failed
    print(f'Worktrees: {report["removable"]} removable, {report["kept"]} kept'
          + ('' if args.remove else ' (dry run; add --remove to remove)'))
    for item in report['worktrees']:
        state = 'removable' if item['removable'] else 'keep'
        print(f'  {state:<9} {item["path"]}' + ('' if item['removable'] else ': ' + '; '.join(item['reasons'])))
    for result in report.get('results', []):
        print(f'  {result["result"]:<9} {result["path"]}' + (f': {result["error"]}' if result.get('error') else ''))
    return failed


def _snapshot(args: argparse.Namespace) -> int:
    if not args.target:
        print('getzilla cleanup snapshot: give a commit, or --remove with a snapshot path', file=sys.stderr)
        return 2
    root = find_root()
    try:
        if args.remove:
            result = review_snapshot.remove(root, args.target)
        else:
            result = {'path': str(review_snapshot.create(root, args.target)), 'result': 'created'}
    except WorktreeError as exc:
        print(f'getzilla cleanup: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True) if args.json else
          f'{result["result"]}: {result["path"]}' + (f' ({result["reason"]})' if result.get('reason') else ''))
    return 0 if result['result'] in {'created', 'removed', 'absent'} else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='getzilla cleanup', description=__doc__.split('\n')[0])
    parser.add_argument('command', choices=['inventory', 'worktrees', 'snapshot'])
    parser.add_argument('target', nargs='?', help='snapshot: the commit to copy, or with --remove the snapshot path')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--temp', help='inventory: temp directory to scan (default: the system temp directory)')
    parser.add_argument('--remove', action='store_true',
                        help='worktrees: remove the removable ones; snapshot: remove the given snapshot')
    args = parser.parse_intermixed_args(argv)
    if args.command == 'snapshot':
        return _snapshot(args)
    return _worktrees(args) if args.command == 'worktrees' else _inventory(args)


if __name__ == '__main__':
    raise SystemExit(main())
