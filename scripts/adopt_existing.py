#!/usr/bin/env python3
"""Adopt an existing folder without Git into a new local Getzilla workspace (Zero-Git).

  getzilla adopt plan   --source DIR --target NEW_DIR [--policy policy.json] [--output plan.json]
  getzilla adopt apply  --plan plan.json --plan-digest SHA256 --writers-stopped [--state-root DIR]
  getzilla adopt status --operation-id op-... [--state-root DIR]
  getzilla adopt resume --operation-id op-... --writers-stopped [--state-root DIR]
  getzilla adopt abort  --operation-id op-... [--state-root DIR]

The source folder is never written. The plan is read-only; apply needs the exact plan digest and
the acknowledgement that every writer of the source is stopped. The result is a new local folder
with a source-only commit and a Getzilla commit; no remote is created and nothing is pushed.
stdout carries one JSON envelope; exit codes: 0 ok, 2 arguments/schema, 3 security block,
4 unsafe/unsupported filesystem, 5 stale plan/source drift, 6 operation/target conflict,
7 verification failure, 8 tool/internal error.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.adoption_state import default_state_root  # noqa: E402
from getzilla.project_adoption import (  # noqa: E402
    abort_adoption, exit_code, get_adoption_status, resume_adoption, run_adoption,
)
from getzilla.source_admission import plan_source  # noqa: E402
from getzilla.source_models import AdmissionPlan, ContractError, IngestPolicy  # noqa: E402
from getzilla.source_paths import source_target_problem  # noqa: E402
from getzilla.source_snapshot import AdoptionError  # noqa: E402

SCHEMA = 'getzilla-adopt-cli-v1'
PLAN_EXIT = {'PLAN_READY': 0, 'BLOCKED_SECURITY': 3, 'BLOCKED_UNSAFE_SOURCE': 4, 'BLOCKED_UNSUPPORTED_FS': 4,
             'STALE_PLAN': 5, 'ERROR': 8}


def envelope(status: str, *, operation_id: str | None = None, reason_code: str | None = None,
             details: object = None) -> dict:
    return {'schema_version': SCHEMA, 'operation_id': operation_id, 'status': status, 'reason_code': reason_code,
            'details': details}


def emit(record: dict, code: int) -> int:
    sys.stdout.write(json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + '\n')
    sys.stdout.flush()
    return code


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='getzilla adopt', description=__doc__.split('\n\n')[0])
    commands = parser.add_subparsers(dest='command', required=True)
    plan = commands.add_parser('plan', help='read-only admission plan')
    plan.add_argument('--source', required=True, type=Path)
    plan.add_argument('--target', required=True, type=Path)
    plan.add_argument('--policy', type=Path)
    plan.add_argument('--output', type=Path)
    apply = commands.add_parser('apply', help='create the local adopted workspace from an approved plan')
    apply.add_argument('--plan', required=True, type=Path)
    apply.add_argument('--plan-digest', required=True)
    apply.add_argument('--writers-stopped', action='store_true')
    for name, help_text in (('status', 'read an operation'), ('resume', 'continue an interrupted operation'),
                            ('abort', 'remove an unpublished operation\'s staging')):
        command = commands.add_parser(name, help=help_text)
        command.add_argument('--operation-id', required=True)
        if name == 'resume':
            command.add_argument('--writers-stopped', action='store_true')
    for command in commands.choices.values():
        command.add_argument('--state-root', type=Path)
    return parser


def _outside_source(path: Path, source: Path) -> bool:
    return source_target_problem(source, path) is None


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return 0 if exc.code == 0 else emit(envelope('failed', reason_code='INVALID_ARGUMENTS'), 2)
    state_root = args.state_root or default_state_root()
    try:
        if args.command == 'plan':
            if (args.source / '.git').exists() or any((parent / '.git').exists() for parent in args.source.resolve().parents):
                return emit(envelope('blocked', reason_code='GIT_PRESENT',
                                     details='the source is a Git repository or inside one: not a Zero-Git input'), 4)
            policy = IngestPolicy()
            if args.policy:
                policy = IngestPolicy.from_dict(json.loads(args.policy.read_text(encoding='utf-8')))
            if args.output and not _outside_source(args.output, args.source):
                return emit(envelope('failed', reason_code='INVALID_ARGUMENTS', details='--output must be outside the source'), 2)
            plan = plan_source(args.source, args.target, policy)
            record = envelope(plan.status.lower(), reason_code=None if plan.status == 'PLAN_READY' else plan.status,
                              details={'plan_id': plan.plan_id, 'plan': plan.to_dict()})
            if args.output:
                args.output.write_text(json.dumps(plan.to_dict(), sort_keys=True, indent=2, ensure_ascii=False) + '\n',
                                       encoding='utf-8', newline='\n')
            return emit(record, PLAN_EXIT.get(plan.status, 8))
        home = Path(os.environ.get('GETZILLA_HOME') or ROOT)
        if args.command == 'apply':
            if not args.writers_stopped:
                return emit(envelope('failed', reason_code='QUIESCENCE_REQUIRED',
                                     details='stop every writer of the source, then pass --writers-stopped'), 2)
            plan = AdmissionPlan.from_dict(json.loads(args.plan.read_text(encoding='utf-8')))
            receipt = run_adoption(plan, args.plan_digest, quiesced=True, home=home, state_root=state_root)
            return emit(envelope('published', operation_id=receipt['operation_id'], details=receipt), 0)
        if args.command == 'resume':
            if not args.writers_stopped:
                return emit(envelope('failed', operation_id=args.operation_id, reason_code='QUIESCENCE_REQUIRED'), 2)
            receipt = resume_adoption(args.operation_id, quiesced=True, home=home, state_root=state_root)
            return emit(envelope('published', operation_id=args.operation_id, details=receipt), 0)
        if args.command == 'abort':
            return emit(envelope('aborted', operation_id=args.operation_id,
                                 details=abort_adoption(args.operation_id, state_root=state_root)), 0)
        state = get_adoption_status(args.operation_id, state_root=state_root)
        # Reading succeeded: exit 0 even when the operation itself failed.
        return emit(envelope(state['state'].lower(), operation_id=args.operation_id, reason_code=state['reason_code'],
                             details=state), 0)
    except AdoptionError as exc:
        return emit(envelope('failed', operation_id=getattr(args, 'operation_id', None), reason_code=exc.reason_code,
                             details=str(exc)), exit_code(exc.reason_code))
    except (ContractError, KeyError, ValueError) as exc:
        return emit(envelope('failed', reason_code='INVALID_ARGUMENTS', details=str(exc)[:500]), 2)
    except OSError as exc:
        return emit(envelope('failed', reason_code='TOOL_ERROR', details=f'{type(exc).__name__}: {exc}'[:500]), 8)


if __name__ == '__main__':
    raise SystemExit(main())
