#!/usr/bin/env python3
"""Assess an explicit local skill; never acquire dependencies or execute its prose."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.component_state import BoundRoot  # noqa: E402
from getzilla.skill_onboarding import install_external, interview, installation_context  # noqa: E402
from getzilla.policy import evaluate_pre_tool  # noqa: E402
from getzilla.skill_preflight import (  # noqa: E402
    CATALOG_PATH, DESCRIPTOR, MAX_DESCRIPTOR_BYTES, MAX_TOTAL_BYTES, assess, read_snapshot, native_contract,
)
from getzilla.state import bind_session  # noqa: E402
from getzilla.util import find_root  # noqa: E402



def _unknown_publication(error: BaseException) -> bool:
    """Read only the known scalar flag through a bounded exception graph.

    A truncated cause/context graph is conservatively inspection-required. Never
    parse notes or exception text, and never serialize arbitrary error attributes.
    """
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        if len(seen) >= 8:
            return True
        seen.add(id(current))
        try:
            # Calling __getattribute__ still dispatches subclass descriptors.
            # Use only the trusted base-owned storage descriptors and dict APIs.
            values = BaseException.__dict__['__dict__'].__get__(current, BaseException)
            if not isinstance(values, dict) or dict.__len__(values) > 64:
                return True
            # Unknown keys could run equality hooks inside even builtin dict.get.
            if any(type(key) is not str for key in dict.keys(values)):
                return True
            missing = object()
            state = dict.get(values, 'publication_state', missing)
            if state is not missing and (type(state) is not str or state == 'unknown'):
                return True
            for name in ('__cause__', '__context__'):
                linked = BaseException.__dict__[name].__get__(current, BaseException)
                if linked is not None:
                    if not issubclass(type(linked), BaseException):
                        return True
                    pending.append(linked)
        except BaseException:
            # Unreadable metadata is uncertainty, never a secondary traceback.
            return True
    return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('assess', 'interview', 'install'))
    parser.add_argument('source', help='explicit project-relative intake directory')
    parser.add_argument('--root', type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve() if args.root else find_root()
    try:
        if args.operation == 'install':
            bind_session(os.environ.get('GETZILLA_SESSION_ID') or os.environ.get('CLAUDE_CODE_SESSION_ID'))
            result = install_external(root, args.source)
            code = 0
        else:
            snapshot = read_snapshot(root, args.source)
            with BoundRoot(root) as binding:
                descriptor = binding.read(args.source + '/' + DESCRIPTOR, limit=MAX_DESCRIPTOR_BYTES)
                catalog = binding.read(CATALOG_PATH, limit=MAX_TOTAL_BYTES)
            if descriptor is None or catalog is None:
                raise ValueError('MISSING_SOURCE_METADATA')
            assessment = assess(snapshot, descriptor.content, catalog.content)
            existing = installation_context(root, catalog.content, assessment.skill_id) if assessment.verdict == 'allow' else ()
            assessment = assess(snapshot, descriptor.content, catalog.content, existing=existing)
            if any(operation != 'read' or not evaluate_pre_tool(root, {
                    'tool_name': 'Read', 'tool_input': {'file_path': resource}})[0]
                   for operation, resource, _exclusive in assessment.capabilities):
                assessment = replace(assessment, verdict='deny', reasons=tuple(sorted({*assessment.reasons, 'CURRENT_POLICY_DENIED'})))
            if args.operation == 'interview':
                result = interview(snapshot, descriptor.content, catalog.content, existing=existing)
                result['assessment'] = assessment.to_dict()
                code = 0 if assessment.verdict == 'allow' else 2
            else:
                if assessment.verdict == 'allow' and native_contract(dict(snapshot.files)['SKILL.md']) is None:
                    assessment = replace(assessment, verdict='needs_review', reasons=('NATIVE_SKILL_FORMAT_REQUIRED',))
                result = assessment.to_dict()
                code = 0 if assessment.verdict == 'allow' else 2
        print(json.dumps(result, sort_keys=True))
        return code
    except BaseException as exc:
        if _unknown_publication(exc):
            print(json.dumps({'schema_version': 1, 'status': 'unknown',
                              'reason': 'PUBLICATION_CUSTODY_UNKNOWN', 'reasons': [],
                              'publication_state': 'unknown', 'inspection_required': True, 'retryable': False,
                              'permissions_granted': False, 'activated': False, 'evidence_valid': False}, sort_keys=True))
            if not issubclass(type(exc), (ValueError, OSError)):
                raise
            return 2
        if not issubclass(type(exc), (ValueError, OSError)):
            raise
        # No raw source, command, exception text or credentials enter diagnostics.
        prefix, _separator, detail = str(exc).partition(':')
        reason = prefix if re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', prefix) else 'AUTHORITY_OR_INPUT_REFUSED'
        codes = detail.strip().split(',') if detail.strip() else []
        reasons = codes if len(codes) <= 32 and all(re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', code) for code in codes) else []
        print(json.dumps({'schema_version': 1, 'status': 'refused', 'reason': reason, 'reasons': reasons,
                          'permissions_granted': False, 'evidence_valid': False}, sort_keys=True))
        return 2


def _terminal_unknown_exit(error: BaseException) -> int:
    """Bounded public exit codes; never print a private SystemExit payload."""
    if issubclass(type(error), KeyboardInterrupt):
        return 130
    if issubclass(type(error), SystemExit):
        try:
            code = SystemExit.__dict__['code'].__get__(error, SystemExit)
        except BaseException:
            return 1
        if type(code) is int and -(2 ** 31) <= code < 2 ** 31:
            effective = code & (0xFFFFFFFF if os.name == 'nt' else 0xFF)
            if effective:
                return code
    return 1


def _entrypoint():
    # Direct main() callers retain the original interrupt/exit instance. Only the
    # terminal boundary converts a recognized unknown into a private-text-free
    # failing exit; no global exception hook or automatic retry is installed.
    try:
        return main()
    except BaseException as error:
        if _unknown_publication(error):
            return _terminal_unknown_exit(error)
        raise


if __name__ == '__main__':
    raise SystemExit(_entrypoint())
