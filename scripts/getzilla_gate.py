from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.human_gates import ARTIFACT_NOTICE, GATE_ACTIONS, gate_statuses, record_gate_decision
from getzilla.util import find_root

parser = argparse.ArgumentParser(
    description="Inspect or record an explicit local decision for a route-declared human gate."
)
commands = parser.add_subparsers(dest="command", required=True)
commands.add_parser("status", help="Show the active route's gate states")
decide = commands.add_parser("decide", help="Record an explicit approve/reject decision")
decide.add_argument("gate", choices=sorted(GATE_ACTIONS))
decide.add_argument("decision", choices=["approved", "rejected"])
decide.add_argument("--reason", required=True)
decide.add_argument("--actor", required=True, help="Operator label; it is not cryptographically authenticated")
decide.add_argument("--action", help="Exact production action, migration-plan, external-write or paid-run action approved")
decide.add_argument("--resource", help="Exact external-write or paid-run resource approved (n8n, a provider host or a file)")
args = parser.parse_args()
root = find_root()

if args.command == "status":
    output = {
        "human_gates": gate_statuses(root),
        "local_workflow_evidence_only": True,
        "notice": ARTIFACT_NOTICE,
    }
else:
    try:
        result = record_gate_decision(
            root,
            args.gate,
            args.decision,
            args.reason,
            actor=args.actor,
            action=args.action,
            resource=args.resource,
        )
    except ValueError as exc:
        parser.error(str(exc))
    output = {
        "decision": result,
        "local_workflow_evidence_only": True,
        "notice": ARTIFACT_NOTICE,
    }

print(json.dumps(output, ensure_ascii=False, indent=2))
