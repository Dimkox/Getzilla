"""Inspect public source trust declarations offline. This command grants no authority."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.supply_chain import audit  # noqa: E402
from getzilla.util import find_root  # noqa: E402


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # Untrusted argument values can contain private data. Emit only a fixed code.
        print(json.dumps({'error': 'invalid-arguments'}))
        raise SystemExit(2)


def main() -> int:
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('audit', help='hash the bounded existing source inventory')
    inspect.add_argument('--json', action='store_true')
    args = parser.parse_args()
    report = audit(find_root())
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print('Offline source observation; authority: none; external MCP identity: unsupported.')
        for entry in report['sources']:
            print(f"{entry['state']}: {entry['path']}")
    return 0 if report['audit_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
