from __future__ import annotations

import argparse
import json
import os
import sys
sys.dont_write_bytecode = True
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.state import add_approval, bind_session, extend_protected_path_approval
from getzilla.util import find_root

RELEASE_ACTIONS = ['git-push-branch', 'git-push-tag', 'github-release']

parser = argparse.ArgumentParser(
    description=(
        'Materialize an explicitly delegated local grant bound to the current '
        'repository, route, change and TTL. Protected edits bind the branch and exact files; '
        'production/external operations bind exact Git HEAD and tree. Local grants '
        'never satisfy external Trust CI approvals.'
    )
)
parser.add_argument('scope', choices=['production', 'external-write', 'protected-path'])
parser.add_argument('--reason', required=True)
parser.add_argument('--ttl', type=int, default=15, help='Minutes; 1..1440')
parser.add_argument('--extend', help='Existing protected grant ID; explicitly replace its full literal file set')
parser.add_argument('--request-id', help='Stable 32-character lowercase hex ID for this extension request')
parser.add_argument(
    '--source',
    choices=['standing-user-consent', 'explicit-user-consent'],
    default='standing-user-consent',
)
parser.add_argument(
    '--profile',
    choices=['release'],
    help='Named action bundle. release = branch push + tag push + GitHub Release.',
)
parser.add_argument(
    '--action',
    action='append',
    default=[],
    choices=[
        'git-push-branch',
        'git-push-tag',
        'pull-request-merge',
        'docker-push',
        'npm-publish',
        'github-release',
        'external-write',
        'protected-path-write',
    ],
)
parser.add_argument(
    '--resource',
    action='append',
    default=[],
    help=(
        'Exact repository-relative path, MCP tool name or URL for protected/external grants. '
        'Production grants require a branch, tag, owner/repo#N, owner/repo@tag, image or name@version. '
        'Repeat for several resources; wildcard patterns are refused.'
    ),
)
args = parser.parse_args()
if (args.extend is None) != (args.request_id is None):
    parser.error('INVALID_EXTENSION_REQUEST')
if args.extend is not None and (args.scope != 'protected-path' or args.profile is not None):
    parser.error('UNSUPPORTED_EXTENSION_SCOPE')

actions = list(args.action)
if args.profile == 'release':
    if args.scope != 'production':
        parser.error('--profile release is valid only for production scope')
    actions.extend(RELEASE_ACTIONS)
if not actions:
    parser.error('at least one --action or --profile is required')

# Explicit caller identity never transfers a grant to another task or authority epoch.
bind_session(os.environ.get('GETZILLA_SESSION_ID') or os.environ.get('CLAUDE_CODE_SESSION_ID'))
root = find_root()
try:
    if args.extend is not None:
        result = extend_protected_path_approval(
            root, args.extend, args.request_id, args.reason, args.ttl,
            actions=actions, resources=args.resource, source=args.source,
        )
    else:
        result = add_approval(
            root, args.scope, args.reason, args.ttl,
            actions=actions, resources=args.resource, source=args.source,
        )
except ValueError as exc:
    parser.error(str(exc))
if result.get('route_id'):
    from getzilla.sprint_lifecycle import flush_after_scope
    flush_after_scope(root, result['route_id'])
result['external_trust_ci_authority'] = False
result['notice'] = (
    'This delegated local grant authorizes only the listed operation on the '
    'bound branch/file set for protected edits, or exact current tree for other scopes. '
    'It cannot create adaptive-trust-ci/verified or a '
    'human-signed Trust CI approval.'
)
print(json.dumps(result, ensure_ascii=False, indent=2))
if args.extend is not None and result['status'] not in {'created', 'replayed'}:
    raise SystemExit(2 if result['status'] == 'refused' else 1)
