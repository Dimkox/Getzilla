#!/usr/bin/env python3
"""Does the ritual pay for itself? Per-profile overhead and defects caught before merge.

  getzilla report [--since 7d|24h|all] [--json]

Reads .getzilla/runtime/metrics.jsonl (routes, verification runs, receipts) and the path-hint and
parallel-guard counters. Everything is local; nothing is sent anywhere.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.route_metrics import counters, load, summarize  # noqa: E402
from getzilla.util import find_root  # noqa: E402


def _since(value: str) -> datetime | None:
    if value == 'all':
        return None
    match = re.fullmatch(r'(\d+)([dh])', value)
    if not match:
        raise SystemExit('--since takes Nd, Nh or all')
    amount = int(match.group(1))
    return datetime.now(timezone.utc) - (timedelta(days=amount) if match.group(2) == 'd' else timedelta(hours=amount))


def _cell(value: object) -> str:
    return '-' if value is None else str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='getzilla report', description=__doc__.split('\n')[0])
    parser.add_argument('--since', default='7d', help='period: Nd, Nh or all (default 7d)')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    root = find_root()
    summary = summarize(load(root, _since(args.since)))
    summary['counters'] = counters(root)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    print(f'Getzilla report, last {args.since}: {len(summary["routes"])} route(s)')
    if summary['profiles']:
        print(f'{"profile":<10} {"routes":>6} {"median min to pass":>19} {"verify runs/route":>18} {"reviews":>8} {"caught before merge":>20}')
        for name, group in sorted(summary['profiles'].items()):
            print(f'{name:<10} {group["routes"]:>6} {_cell(group["median_minutes_to_pass"]):>19} '
                  f'{group["verify_runs_per_route"]:>18} {group["reviews"]:>8} {group["caught_before_merge"]:>20}')
    else:
        print('No routes recorded yet: metrics start with the next route and verification run.')
    hints = summary['counters'].get('path_hints', {})
    guard = summary['counters'].get('parallel_guard', {})
    if hints or guard:
        serial = ', '.join(f'{key} {value}' for key, value in sorted(guard.items()) if key != 'since') or '0'
        print(f'Path misses answered with real paths: {hints.get("refused", 0)} refused, {hints.get("hinted", 0)} hinted.')
        print(f'Serial batches sent to the parallel runner: {serial}.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
