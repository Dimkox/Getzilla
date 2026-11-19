"""Audit unsealed public retrieval experiment inputs; never run a ranker or model."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.retrieval.budget import RetrievalError
from getzilla.retrieval.evaluation_inputs_io import audit_directory


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        print(json.dumps({'status': 'unavailable', 'reason': 'invalid_arguments'}))
        raise SystemExit(2)


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument('candidate', type=Path, help='directory containing the four registered draft JSON artifacts')
    parser.add_argument('--public-source-root', type=Path, required=True, help='fixed public corpus artifact directory')
    parser.add_argument('--require-ranking', action='store_true', help='refuse unsealed draft inputs explicitly')
    args = parser.parse_args(argv)
    try:
        result = audit_directory(args.candidate, args.public_source_root)
        if args.require_ranking:
            result.require_rankable()
        print(json.dumps(result.to_dict(), sort_keys=True))
        return 0
    except RetrievalError as exc:
        reason = str(exc)
        status = 'inconclusive' if reason == 'independent_seals_required' else 'unavailable'
        print(json.dumps({'status': status, 'reason': reason}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
