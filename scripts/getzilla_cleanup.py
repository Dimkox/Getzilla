#!/usr/bin/env python3
"""What Getzilla leaves on disk: a read-only inventory of runtime state and temp directories.

  getzilla cleanup inventory [--json] [--temp DIR]

Classes: protected (state, receipts, evidence, worktrees), ephemeral (reproducible output) and
unknown (never deleted without an owner record). This command deletes nothing.
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


def _size(value: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB'):
        if value < 1024 or unit == 'GB':
            return f'{value:.0f} {unit}' if unit == 'B' else f'{value:.1f} {unit}'
        value /= 1024
    return f'{value} B'  # pragma: no cover


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='getzilla cleanup', description=__doc__.split('\n')[0])
    parser.add_argument('command', choices=['inventory'])
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--temp', help='temp directory to scan (default: the system temp directory)')
    args = parser.parse_args(argv)
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
    if not report['complete']:
        print('Some sizes are incomplete: unreadable entries or the entry budget was reached.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
