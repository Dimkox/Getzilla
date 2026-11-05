#!/usr/bin/env python3
"""Native installer observations and their fail-closed aggregate; no security approval authority."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'.getzilla'))
from getzilla.platform_install import load_artifacts, load_contract, native_platform, validate_results  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument('--matrix', action='store_true')
    actions.add_argument('--check-platform')
    actions.add_argument('--cell')
    actions.add_argument('--aggregate', type=Path)
    actions.add_argument('--restore-stable-payload', type=Path, metavar='VERIFIED_V230_CHECKOUT')
    parser.add_argument('--workspace', type=Path)
    parser.add_argument('--project', type=Path, help='absent target for the exact historical payload restore')
    parser.add_argument('--head')
    parser.add_argument('--job-result', default='missing')
    args = parser.parse_args(argv)
    try:
        contract = load_contract(ROOT)
        required = [c for c in contract['cells'] if c['required']]
        if args.restore_stable_payload is not None:
            if args.project is None:
                raise ValueError('--restore-stable-payload requires an absent --project target')
            from getzilla.install_baseline import restore_release_payload
            print(json.dumps(restore_release_payload(ROOT, args.restore_stable_payload, args.project)))
            return 0
        if args.matrix:
            print(json.dumps({'include': required}, separators=(',', ':')))
            return 0
        if args.check_platform:
            actual = native_platform(platform.system(), platform.machine())
            wanted = next((c for c in contract['cells'] if c['id'] == args.check_platform and c['supported']), None)
            if not wanted or actual != (wanted['os'], wanted['arch']):
                raise ValueError('native runner OS/architecture does not match the selected supported platform')
            print(json.dumps({'platform': wanted['id'], 'actual': actual, 'machine': platform.machine()}))
            return 0
        if not args.head or not re.fullmatch(r'(?:[a-f0-9]{40}|[a-f0-9]{64})', args.head):
            raise ValueError('--head requires the exact expected candidate SHA')
        if args.cell:
            if args.workspace is None:
                raise ValueError('--workspace must be a new private directory')
            from getzilla.platform_acceptance import run_cell
            record = run_cell(ROOT, args.workspace, cell_id=args.cell, expected_head=args.head)
            print(json.dumps({'cell': record['cell'], 'scenarios': record['scenarios'],
                              'seconds': record['seconds'], 'authority': record['authority'],
                              'error': record.get('error')}))
            return 0 if not record.get('error') and all(s.get('status') == 'pass' for s in record['scenarios'].values()) else 1
        records = load_artifacts(args.aggregate, maximum=len(required))
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT,
                                       text=True, encoding='utf-8', timeout=20).strip()
        tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT,
                                       text=True, encoding='utf-8', timeout=20).strip()
        if head != args.head:
            raise ValueError('aggregate checkout differs from expected candidate SHA')
        problems = validate_results(records, matrix=contract['cells'], required=[c['id'] for c in required],
                    repository=os.environ.get('GITHUB_REPOSITORY', ''),
                    head=head, tree=tree, run_id=os.environ.get('GITHUB_RUN_ID', ''),
                    run_attempt=os.environ.get('GITHUB_RUN_ATTEMPT', ''), stable=contract['previous_stable'],
                    version=(ROOT/'VERSION').read_text(encoding='utf-8').strip(),
                    cli_sha256=hashlib.sha256((ROOT/'scripts/getzilla_cli.py').read_bytes()).hexdigest(),
                    managed_sha256=hashlib.sha256((ROOT/'scripts/getzilla_doctor.py').read_bytes()).hexdigest(),
                    job_result=args.job_result)
        print(json.dumps({'authority': 'observations-only', 'problems': problems, 'required_cells': len(required)}))
        return int(bool(problems))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'failed', 'authority': 'observations-only', 'error': str(error)[:512]}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
