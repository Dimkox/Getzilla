from __future__ import annotations

import sys
from pathlib import Path

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

import argparse
import json
import os

parser = argparse.ArgumentParser(
    prog='getzilla status',
    description='Print the active route, change package, agents, human gates and evidence gaps as JSON.',
)
parser.add_argument('--model-continuation', action='store_true', help='Print only passive model continuation status.')
parser.add_argument('--harness', choices=('grok', 'qwen', 'claude', 'codex', 'gemini', 'copilot'),
                    help='Identify the native harness; this does not qualify an adapter.')
args = parser.parse_args()

from getzilla.package_status import collect_worktree, inspect_package, receipt_inputs_unavailable
from getzilla.receipts import validate_evidence
from getzilla.human_gates import ARTIFACT_NOTICE, gate_statuses
from getzilla.agent_lifecycle import watchdog
from getzilla.state import get_active_change, get_active_route, get_agent_state
from getzilla.util import find_root
from getzilla.model_continuation import startup_status

root = find_root()
continuation = startup_status(root, args.harness or 'unknown')
if args.model_continuation:
    print(json.dumps(continuation, ensure_ascii=True, indent=2))
    raise SystemExit(0)
# Applies to existing receipt-validation Git reads as well as the new snapshot.
os.environ['GIT_OPTIONAL_LOCKS'] = '0'
route = get_active_route(root)
active = get_active_change(root)
package = inspect_package(root, route, active)
worktree = collect_worktree(root, route, package['initial_checkpoint'])
evidence_gaps = []
if route:
    evidence_gaps = (
        ['package: receipt validation unavailable until unsafe or unreadable selected inputs are resolved']
        if receipt_inputs_unavailable(package) else validate_evidence(root, route)
    )
print(json.dumps({
    'model_continuation': continuation,
    'route': route,
    'change': active,
    'agents': get_agent_state(root),
    'agent_diagnostics': watchdog(root),
    'human_gates': gate_statuses(root),
    'human_gate_notice': ARTIFACT_NOTICE,
    'evidence_gaps': evidence_gaps,
    'package_completeness': package,
    'package_incomplete': package['findings'],
    'worktree': worktree,
}, ensure_ascii=True, indent=2))
