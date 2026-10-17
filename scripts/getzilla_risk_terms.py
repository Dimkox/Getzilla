#!/usr/bin/env python3
"""Risk vocabulary language packs: English is the base, agents translate packs for other languages.

  getzilla risk-terms check                         validate the base and every pack (exit 1 on problems)
  getzilla risk-terms scaffold --lang de --script LATIN [--output FILE]
                                                    print or write a pack skeleton to translate
  getzilla risk-terms languages                     list installed packs and the scripts they cover
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.risk_terms import DEFAULT_DIR, RiskTermsError, check_packs, load_vocabulary, scaffold  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='getzilla risk-terms', description=__doc__.split('\n')[0])
    parser.add_argument('--dir', type=Path, default=DEFAULT_DIR, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest='command')
    sub.add_parser('check')
    sub.add_parser('languages')
    make = sub.add_parser('scaffold')
    make.add_argument('--lang', required=True)
    make.add_argument('--script', required=True, help='Unicode script of the language, for example LATIN, CJK, ARABIC')
    make.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    if args.command == 'check':
        problems = check_packs(args.dir)
        print(json.dumps({'ok': not problems, 'problems': problems}, ensure_ascii=False, indent=2))
        return 1 if problems else 0
    if args.command == 'languages':
        vocabulary = load_vocabulary(args.dir)
        print(json.dumps({'languages': list(vocabulary.languages), 'scripts': sorted(vocabulary.scripts)}, indent=2))
        return 0
    if args.command == 'scaffold':
        try:
            pack = scaffold(args.lang, args.script, args.dir)
        except RiskTermsError as error:
            print(json.dumps({'ok': False, 'error': str(error)}))
            return 2
        text = json.dumps(pack, ensure_ascii=False, indent=2) + '\n'
        if args.output:
            if args.output.exists():
                print(json.dumps({'ok': False, 'error': f'{args.output} exists'}))
                return 2
            args.output.write_text(text, encoding='utf-8', newline='\n')
        else:
            sys.stdout.write(text)
        return 0
    parser.print_help()
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
