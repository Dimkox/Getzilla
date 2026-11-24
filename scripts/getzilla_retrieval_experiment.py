"""Optional public research facts. No model acquisition, worker or ranking."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        print(json.dumps({'status': 'unavailable', 'reason': 'invalid_arguments', 'ranking_permitted': False}))
        raise SystemExit(2)


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('action', choices=('status', 'input-audit', 'execute', 'witness-public-reviews', 'observe-public-producer'))
    parser.add_argument('--registration', type=Path, help='Private bounded public review facts; not authority')
    parser.add_argument('--session', help='Existing current task owner session for explicit witness action')
    parser.add_argument('--candidate', type=Path)
    parser.add_argument('--public-source-root', type=Path)
    args = parser.parse_args(argv)
    from getzilla.retrieval.experiment_evidence import status
    if args.action == 'status':
        print(json.dumps({**status(), 'execution_enabled': False, 'module_selection': 'not_observed'}, sort_keys=True))
        return 0
    if args.action in ('witness-public-reviews', 'observe-public-producer'):
        if args.registration is None or args.session is None:
            print(json.dumps({'status': 'unavailable', 'reason': 'invalid_arguments', 'ranking_permitted': False}))
            return 2
        from getzilla.state import bind_session
        from getzilla.retrieval.public_review_witness import witness_public_reviews, consume_public_reviews, observe_public_producer
        bind_session(args.session)
        try:
            if args.action == 'observe-public-producer':
                facts = observe_public_producer(ROOT, str(args.registration))
            else:
                reference = witness_public_reviews(ROOT, str(args.registration))
                facts = consume_public_reviews(reference)
            print(json.dumps({'status': 'observed', **facts}, sort_keys=True))
            return 0
        except Exception:
            print(json.dumps({'status': 'unavailable', 'reason': 'public_review_witness_unavailable', 'ranking_permitted': False}))
            return 2
        finally:
            bind_session(None)
    if args.action == 'execute':
        print(json.dumps(status(), sort_keys=True))
        return 2
    from getzilla.optional_modules import admit_module
    if not admit_module(ROOT, 'retrieval-research').get('allowed'):
        print(json.dumps({'status': 'disabled', 'ranking_permitted': False}, sort_keys=True))
        return 2
    if args.candidate is None or args.public_source_root is None:
        print(json.dumps({'status': 'unavailable', 'reason': 'input_missing', 'ranking_permitted': False}))
        return 2
    from getzilla.retrieval.evaluation_inputs_io import audit_directory
    from getzilla.retrieval.budget import RetrievalError
    try:
        facts = audit_directory(args.candidate, args.public_source_root).to_dict()
        print(json.dumps({**facts, 'promotion': status()}, sort_keys=True))
        return 0
    except RetrievalError:
        print(json.dumps({'status': 'unavailable', 'reason': 'input_unavailable', 'ranking_permitted': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
