#!/usr/bin/env python3
"""Shared context command and explicit ordinary-text delivery adapter."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.retrieval.budget import RetrievalError  # noqa: E402
from getzilla.retrieval.transport import MAX_TEXT_BYTES, deliver_text  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    query = sub.add_parser('query')
    query.add_argument('--root', required=True)
    query.add_argument('--query', required=True)
    query.add_argument('--format', choices=('json', 'text'), default='json')
    query.add_argument('--mandatory-stdin', action='store_true')
    delivery = sub.add_parser('deliver', help='pass caller-supplied ordinary text to an explicit client')
    delivery.add_argument('--transport', required=True)
    delivery.add_argument('--scratch', help='owned0700 runtime directory required for file transport')
    delivery.add_argument('--timeout', type=float, default=30)
    delivery.add_argument('client', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command == 'query':
        from getzilla.retrieval.native_local import CONTEXT_REASONS, deliver_local_context
        try:
            mandatory = ''
            if args.mandatory_stdin:
                raw = sys.stdin.buffer.read(16385)
                if len(raw) > 16384:
                    raise RetrievalError('mandatory_budget_exceeded')
                mandatory = raw.decode('utf-8')
            result = deliver_local_context(Path(args.root), args.query, mandatory, output_format=args.format)
            return 0 if result['status'] == 'issued' else 3
        except (ValueError, OSError) as error:
            from getzilla.native_access import NativeAccessError
            if isinstance(error, NativeAccessError) and error.code == 'native_access_outcome_unknown':
                print('native_access_outcome_unknown', file=sys.stderr)
                return 3
            reason = str(error) if str(error) in CONTEXT_REASONS else 'authority_unavailable'
            print(json.dumps({'schema': 'getzilla-context-cli-v1', 'status': 'unavailable',
                              'reason': reason, 'model_calls': 0}))
            return 3
    try:
        raw = sys.stdin.buffer.read(MAX_TEXT_BYTES + 1)
        if len(raw) > MAX_TEXT_BYTES:
            raise RetrievalError('context_bytes_exceeded')
        try:
            text = raw.decode('utf-8')
        except UnicodeError:
            raise RetrievalError('context_encoding_unavailable') from None
        client = args.client[1:] if args.client[:1] == ['--'] else args.client
        return deliver_text(text, client, transport=args.transport, scratch=args.scratch, timeout=args.timeout)
    except RetrievalError as error:
        print(str(error), file=sys.stderr)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
