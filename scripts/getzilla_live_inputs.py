"""Prepare pinned cp313/Linux wheels before the offline disposable Trust cell."""
import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.live_contracts import wheelhouse_command, validate_wheelhouse
from getzilla.python_test_runner import execute, cleanup_details


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wheelhouse', required=True, type=Path)
    args = parser.parse_args()
    args.wheelhouse.mkdir(mode=0o700, parents=True, exist_ok=False)
    lock = ROOT / 'trust-ci/requirements-test.txt'
    result = execute(wheelhouse_command(sys.executable, lock, args.wheelhouse), ROOT,
                     dict(os.environ), timeout=180)
    cleanup = cleanup_details(result)
    if (result.returncode or result.terminal_state != 'completed' or cleanup['facts']
            or cleanup['overflow'] or cleanup['unavailable']):
        raise RuntimeError('Pinned live input acquisition failed; offline cell was not started')
    validate_wheelhouse(args.wheelhouse, lock)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
