"""Regenerate/check the exact Core copy of the canonical standalone pure leaf."""
from pathlib import Path
import argparse
import sys

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / 'trust-ci/lock_profile_validation.py'
MIRROR = ROOT / '.getzilla/getzilla/lock_profile_validation.py'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true')
    mode.add_argument('--write', action='store_true')
    args = parser.parse_args()
    body = CANONICAL.read_bytes()
    if args.write:
        MIRROR.write_bytes(body)
    if MIRROR.read_bytes() != body:
        parser.exit(1, 'Core lock validator mirror is stale; regenerate from canonical owner with --write\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
