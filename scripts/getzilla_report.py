#!/usr/bin/env python3
"""Does the ritual pay for itself? Per-profile observations and disclosed coverage gaps.

  getzilla report [--since 7d|24h|all] [--json]

Reads .getzilla/runtime/metrics.jsonl (routes, verification runs, receipts) and the path-hint and
parallel-guard counters. Everything is local; nothing is sent anywhere.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
sys.dont_write_bytecode = True
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.route_metrics import COUNTERS, counters, load, summarize, import_observations  # noqa: E402
from getzilla.util import find_root  # noqa: E402
from getzilla.trace_storage import LocalRead  # noqa: E402
from getzilla.metrics_journal import Observations  # noqa: E402

MAX_GAP_ROUTES = 10


def _disclosure_refusal():
    return {'access': 'metadata_only', 'events': [], 'input_digest': None,
            'scope': 'canonical_root_only', 'gaps': ['disclosure_revalidation_failed']}


def _unavailable_classic(source, since):
    counts = Counter()
    if source.get('input_digest') is not None:
        for row in source.get('events', []):
            try:
                if row.get('schema_version') != 3 and (since is None or datetime.fromisoformat(row['at'].replace('Z', '+00:00')) >= since):
                    counts[row['event']] += 1
            except (ValueError, KeyError, TypeError):
                pass
    return {'schema_version': 1, 'access': 'metadata_only', 'source_scope': 'canonical_root_only',
            'evidence_grade': 'unqualified_legacy_aggregates', 'routes': None, 'profiles': None, 'sessions': None,
            'route_observations': {'complete': False, 'routes': None, 'routes_with_gaps': None},
            'counters': None, 'legacy_event_counts': dict(sorted(counts.items())) if source.get('input_digest') is not None else None,
            'coverage': {'complete': False, 'gaps': sorted(set(source.get('gaps', []) + ['native_observation_read_unavailable']))},
            'interpretation': 'Task and route census unavailable; admitted legacy aggregates are not acceptance.'}


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


def _printable(value: object) -> str:
    """Journal text for the terminal: control and format characters become `?` (#134)."""
    return ''.join(char if char.isprintable() else '?' for char in str(value))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='getzilla report', description=__doc__.split('\n')[0])
    parser.add_argument('--since', default='7d', help='period: Nd, Nh or all (default 7d)')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--import-observations', help='Bounded repository-relative JSON offline observation file')
    parser.add_argument('--sprint-start', help='UTC start of a 14-day canonical-root sprint projection')
    parser.add_argument('--as-of', help='UTC as-known cutoff; required with --sprint-start')
    parser.add_argument('--trace-operation', help='Read local source-bound observations for a native operation ID')
    args = parser.parse_args(argv)
    root = find_root()
    if args.trace_operation is not None:
        if args.sprint_start is not None or args.as_of is None or args.import_observations:
            parser.error('trace mode requires cutoff and cannot select a sprint or import')
        from getzilla.observation_privacy import load_local, revalidate_local
        from getzilla.trace_report import reconstruct
        from getzilla.trace_contracts import utc, delivery_utc
        from getzilla.metrics_journal import digest
        source = load_local(root)
        try:
            until = utc(args.as_of)
            visible = []
            for row in source['events']:
                if row.get('schema_version') != 3:
                    visible.append(row)
                    continue
                proof = source.get('delivery_proofs', {}).get(row['event_id'])
                if proof and proof['row_digest'] == digest(row) and delivery_utc(proof['delivered_by']) <= until:
                    visible.append(row)
                else:
                    source['gaps'].append('native_delivery_proof_missing')
            summary = reconstruct(visible, args.trace_operation, args.as_of)
        except ValueError:
            parser.error('invalid trace input')
        if not revalidate_local(root, source):
            source = _disclosure_refusal()
            summary = reconstruct([], args.trace_operation, args.as_of)
        summary['access'] = source['access']
        summary['source_scope'] = source['scope']
        summary['coverage']['gaps'] = sorted(set(summary['coverage']['gaps'] + source['gaps']))
        if source['access'] == 'metadata_only':
            summary['observations'] = None
            summary['stages'] = {}
        if source['input_digest'] is None:
            summary['legacy_observations'] = None
        if args.json:
            print(json.dumps(summary, sort_keys=True, indent=2))
        else:
            print('Local trace observations: ' + summary['outcome'])
            print('Coverage gaps: ' + '; '.join(summary['coverage']['gaps']))
        return 0
    if args.sprint_start is not None or args.as_of is not None:
        if args.sprint_start is None or args.as_of is None or args.import_observations:
            parser.error('sprint mode requires start and cutoff and cannot import observations')
        from getzilla.observation_privacy import load_local, revalidate_local
        from getzilla.sprint_report import summarize_sprint
        source = load_local(root)
        try:
            summary = summarize_sprint(source['events'], start=args.sprint_start,
                                       as_of=args.as_of, source_manifest=source)
        except ValueError:
            parser.error('invalid sprint input')
        if not revalidate_local(root, source):
            source = _disclosure_refusal()
            summary = summarize_sprint([], start=args.sprint_start, as_of=args.as_of,
                                       source_manifest=source)
        summary['access'] = source['access']
        summary['journal_digest'] = source['input_digest']
        if args.json:
            print(json.dumps(summary, sort_keys=True, indent=2))
        else:
            print('14-day sprint, canonical-root observations only')
            print('Selected: unknown; qualified completion: unknown; forecast: insufficient history')
            print('Observed selected: ' + str(summary['counts']['observed_selected']))
            print('Coverage gaps: ' + '; '.join(summary['coverage']['gaps']))
        return 0
    if args.import_observations:
        import_observations(root, args.import_observations)
    from getzilla.observation_privacy import load_local, revalidate_local
    source = load_local(root)
    since = _since(args.since)
    summary = None
    if source['access'] == 'local_owner':
        try:
            with LocalRead(root) as reader:
                observations = load(root, since, reader=reader)
                if observations.available and observations.input_digest == source['input_digest']:
                    # Native stage data has its own source-bound projections.
                    legacy = [row for row in observations if row.get('schema_version') not in {3, 4}]
                    summary = summarize(Observations(legacy, gaps=observations.gaps), root, reader=reader)
                    if summary['routes'] is not None:
                        summary['counters'] = counters(root, reader=reader)
                        missing = [name for name in COUNTERS if name not in summary['counters']]
                        summary['counter_observations'] = {'complete': not missing,
                            'gaps': ['counter observation unavailable: ' + name for name in missing]}
                    summary['evidence_grade'] = 'unqualified_legacy_observations'
                    summary['source_scope'] = 'canonical_root_only'
                reader.check()
        except (OSError, ValueError):
            summary = None
    if not revalidate_local(root, source):
        source = _disclosure_refusal()
        summary = None
    if summary is None:
        summary = _unavailable_classic(source, since)
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print('Workflow observation census unavailable; current private read boundary is unqualified.')
            print('Coverage gaps: ' + '; '.join(summary['coverage']['gaps']))
        return 0
    return _emit(summary, args)


def _emit(summary, args):
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    if summary['routes'] is None:
        print('Getzilla report: local observation counts unknown.')
        print('Coverage gaps: local observations unavailable')
        return 0
    print(f'Getzilla report, last {args.since}: {len(summary["routes"])} route(s)')
    if summary['profiles']:
        print(f'{"profile":<10} {"routes":>6} {"median min to pass":>19} {"verify runs/route":>18} {"reviews":>8} {"failed outcomes":>20}')
        for name, group in sorted(summary['profiles'].items()):
            print(f'{_printable(name):<10} {group["routes"]:>6} {_cell(group["median_minutes_to_pass"]):>19} '
                  f'{group["verify_runs_per_route"]:>18} {group["reviews"]:>8} {group["failed_check_or_review_outcomes"]:>20}')
    else:
        print('No admitted legacy route observations in this input; coverage may be incomplete.')
    print(summary['interpretation'])
    if summary['coverage']['gaps']:
        print('Coverage gaps: ' + '; '.join(summary['coverage']['gaps']))
    observed = summary['route_observations']
    if not observed['complete']:
        print(f'Route observation gaps ({observed["routes_with_gaps"]} of {observed["routes"]} routes; unknown is not zero):')
        gapped = [route for route in summary['routes'] if route.get('gaps')]
        for route in gapped[:MAX_GAP_ROUTES]:
            print(f'  {_printable(route["route_id"])}: ' + '; '.join(route['gaps']))
        if len(gapped) > MAX_GAP_ROUTES:
            print(f'  ... {len(gapped) - MAX_GAP_ROUTES} more; use --json for all.')
    hints = summary['counters'].get('path_hints', {})
    guard = summary['counters'].get('parallel_guard', {})
    if hints:
        print(f'Path misses answered with real paths: {_cell(hints.get("refused"))} refused, {_cell(hints.get("hinted"))} hinted.')
        print(f'Tasks given the real paths of the files they name: {_cell(hints.get("named"))}; '
              f'patches refused because the file was not read first: {_cell(hints.get("edit_unread_refused"))}.')
    if guard:
        serial = ', '.join(f'{key} {value}' for key, value in sorted(guard.items()) if key != 'since') or 'unknown'
        print(f'Serial batches sent to the parallel runner: {serial}.')
    if summary['counter_observations']['gaps']:
        print('Counter counts unknown: ' + '; '.join(summary['counter_observations']['gaps']))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
