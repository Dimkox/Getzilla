from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

import argparse
import json
import os

from getzilla.continuity import ack_scope, finish_task, submit
from getzilla.package_status import read_package_file
from getzilla.router import route_context
from getzilla.state import bind_session, get_active_route, require_route_owner
from getzilla.util import find_root

parser = argparse.ArgumentParser(description='Create, continue or inspect an exact task route.')
parser.add_argument('task', nargs='?', help='Same-session unfinished task amendment; otherwise an initial task')
parser.add_argument('--session', default=os.environ.get('GETZILLA_SESSION_ID') or os.environ.get('CLAUDE_CODE_SESSION_ID') or 'manual')
actions = parser.add_mutually_exclusive_group()
actions.add_argument('--show', action='store_true')
actions.add_argument('--new-task', metavar='TEXT', help='Deliberate fresh task; refuses open packages and active workers')
actions.add_argument('--continue', dest='continue_route', metavar='ROUTE_ID', help='Exact task selection/handoff')
actions.add_argument('--ack-scope', metavar='JSON_PATH', help='Repository-relative bounded acknowledgment request')
actions.add_argument('--reconcile', action='store_true', help='Derive reviews from the exact committed diff')
parser.add_argument('--add-reviewer', action='append', default=[], help='With --reconcile, retain this explicitly selected reviewer in future plans')
actions.add_argument('--complete', action='store_true')
actions.add_argument('--cancel', action='store_true')
parser.add_argument('--event-id', help='Trusted stable input event ID (not a session ID)')
parser.add_argument('--request-id', help='Idempotent cross-session handoff request ID')
parser.add_argument('--expected-epoch', type=int)
parser.add_argument('--expected-revision', type=int)
parser.add_argument('--json', action='store_true')
args = parser.parse_args()
root = find_root()
bind_session(args.session)
if args.task is not None and any((args.show, args.new_task is not None, args.continue_route, args.ack_scope,
                                  args.reconcile, args.complete, args.cancel)):
    parser.error('positional task cannot be combined with an explicit route action')
if args.add_reviewer and not args.reconcile:
    parser.error('--add-reviewer requires --reconcile')
if any(value is not None for value in (args.request_id, args.expected_epoch, args.expected_revision)) and not args.continue_route:
    parser.error('handoff expectations require --continue')
try:
    if args.reconcile:
        require_route_owner(root)
        from getzilla.review_plan import reconcile_route
        data = reconcile_route(root, additional_reviewers=tuple(args.add_reviewer))
    elif args.complete or args.cancel:
        data = finish_task(root, cancel=args.cancel)
    elif args.ack_scope:
        raw = read_package_file(root, args.ack_scope, 262144)
        from getzilla.spec import _parse_canonical_json
        data = ack_scope(root, _parse_canonical_json(raw, root / args.ack_scope))
    elif args.continue_route or args.new_task is not None or args.task is not None:
        data = submit(root, args.new_task if args.new_task is not None else args.task or '', args.session,
                      new_task=args.new_task is not None, continue_route=args.continue_route,
                      event_id=args.event_id, expected_epoch=args.expected_epoch,
                      expected_revision=args.expected_revision, request_id=args.request_id)
    else:
        data = get_active_route(root)
except (ValueError, RuntimeError, OSError) as exc:
    raise SystemExit(f'Route operation refused: {exc}') from exc
if not data:
    raise SystemExit('No owned active route. Inspect the canonical route and use exact --continue ROUTE_ID --session SESSION.')
print(json.dumps(data, ensure_ascii=False, indent=2) if args.json else route_context(data, root))
