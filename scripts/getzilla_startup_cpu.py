from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

import argparse
import json

from getzilla.startup_cpu import EVIDENCE_RECORD, RUNTIME_RECORD, measure
from getzilla.state import get_active_change
from getzilla.util import dump_json, find_root, runtime_dir

parser = argparse.ArgumentParser(description='Startup CPU step zero: measure and record effective capacity.')
parser.add_argument('--reserve', type=int, default=0,
                    help='keep this many logical CPUs free (owner n-2 ceiling: --reserve 2)')
parser.add_argument('--no-probe', action='store_true', help='skip the child-only affinity-widening probe')
parser.add_argument('--attach', action='store_true',
                    help='also attach the snapshot to the active change package evidence')
parser.add_argument('--json', action='store_true')
args = parser.parse_args()
if args.reserve < 0:
    raise SystemExit('--reserve must not be negative')

root = find_root()
snapshot = measure(reserve=args.reserve, probe=not args.no_probe)
written = [runtime_dir(root) / RUNTIME_RECORD]
if args.attach:
    active = get_active_change(root) or {}
    package = (root / str(active.get('path') or '')).resolve()
    changes = (root / 'engineering/changes').resolve()
    if not active.get('path') or not package.is_relative_to(changes) or not (package / 'state.json').is_file():
        raise SystemExit('No active change package to attach to; run without --attach before routing.')
    snapshot['change_id'] = active.get('change_id')
    written.append(package / EVIDENCE_RECORD)
for path in written:
    dump_json(path, snapshot)
if args.json:
    print(json.dumps(snapshot, ensure_ascii=False, indent=2))
else:
    topology, process = snapshot['topology'], snapshot['process']
    print('CPU STEP ZERO')
    print(f"Topology: {topology['physical_cores']} physical cores / {topology['online_logical_cpus']} logical "
          f"({topology['online_cpus']})")
    print(f"Process: nproc {process['nproc']}, affinity {process['affinity']}")
    print(f"cpuset: {snapshot['effective_cpuset']}; finite quota: {snapshot['finite_quota']}")
    probe = snapshot['probe']
    print(f"Probe: {'not needed' if probe is None else probe['allowed'] or 'failed'}")
    print(f"Chosen capacity: {snapshot['chosen_capacity']} ({'; '.join(snapshot['reasons'])})")
    for item in snapshot['uncertainties']:
        print(f'Uncertainty: {item}')
    for path in written:
        print(f'Recorded: {path.relative_to(root)}')
