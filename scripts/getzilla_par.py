#!/usr/bin/env python3
"""Run independent shell commands in parallel on the verified CPUs.

  getzilla par [-j N] -- "cmd one" "cmd two" ...
  getzilla par [-j N] --each "tests/php/test_*.php" -- php {}

Each command is checked by the repository policy first; when any is refused nothing runs.
Output is a short summary (failures with their last lines); full logs stay in
.getzilla/runtime/par/<run>/. Exit 0 when every command passed, 1 when any failed, 2 when
refused or empty.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.parallel import capacity, expand_each, report, run_batch  # noqa: E402
from getzilla.util import find_root  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='getzilla par', description=__doc__.split('\n')[0])
    parser.add_argument('-j', '--jobs', type=int, help='worker processes (default: the measured capacity)')
    parser.add_argument('--each', action='append', default=[], metavar='GLOB',
                        help='run the command once per matching path; {} is replaced by the quoted path')
    parser.add_argument('--timeout', type=float, help='seconds per command')
    parser.add_argument('--show-all', action='store_true', help='also print the output of passing commands')
    parser.add_argument('commands', nargs='*', help='shell commands (or, with --each, one command template)')
    args = parser.parse_args(argv)
    root = find_root()
    cwd = Path.cwd()
    commands = expand_each(args.each, ' '.join(args.commands), cwd) if args.each else list(args.commands)
    if not commands:
        print('getzilla par: no commands to run')
        return 2
    workers = args.jobs or capacity(root)
    started = time.monotonic()
    jobs, folder = run_batch(root, commands, workers=workers, cwd=cwd, timeout=args.timeout)
    print(report(root, jobs, folder, workers=workers, wall=time.monotonic() - started, show_all=args.show_all))
    if any(job.refused for job in jobs):
        return 2
    return 0 if all(job.returncode == 0 for job in jobs) else 1


if __name__ == '__main__':
    raise SystemExit(main())
