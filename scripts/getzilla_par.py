#!/usr/bin/env python3
"""Run independent shell commands in parallel on the verified CPUs.

  getzilla par [-j N] -- "cmd one" "cmd two" ...
  getzilla par [-j N] --each "tests/php/test_*.php" -- php {}

Each command is checked by the repository policy first; when any is refused nothing runs.
Output is a bounded summary with byte counts and loss flags. Logs retain at most 32 MiB
per batch in .getzilla/runtime/par/<run>/. Truncated output is not full-report evidence.
Exit 0 when every command passed, 1 when any failed, 2 when refused or empty.
"""
from __future__ import annotations

import argparse
import sys
sys.dont_write_bytecode = True
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
    parser.add_argument('--managed-tool', action='append', default=[], help='source-pinned local tool ID; opt-in namespace execution')
    parser.add_argument('--intent', help='stable intent prefix for managed tools')
    parser.add_argument('--wait-seconds', type=float, default=1, help='bounded managed observation, at most30seconds')
    parser.add_argument('commands', nargs='*', help='shell commands (or, with --each, one command template)')
    args = parser.parse_args(argv)
    root = find_root()
    if args.managed_tool:
        import json
        from getzilla import execution, execution_store, supervised_execution
        if (args.commands or args.each or not args.intent or len(args.managed_tool) > 2
                or args.timeout is None or not args.timeout.is_integer()
                or not 0 < args.wait_seconds <= 30):
            print(json.dumps({'error': 'invalid_managed_batch'}))
            return 2
        try:
            attempts = [supervised_execution.start(root, tool_id=tool,
                intent_key=f'{args.intent}.{index}', hard_timeout_seconds=int(args.timeout))
                for index, tool in enumerate(args.managed_tool)]
            results = [supervised_execution.observe(root, item['execution_id'], wait_seconds=args.wait_seconds)
                       for item in attempts]
        except (execution.ExecutionError, execution_store.RegistryError) as error:
            print(json.dumps({'error': error.code}))
            return 2
        print(json.dumps({'profile': supervised_execution.PROFILE, 'attempts': results}))
        return 0
    cwd = Path.cwd()
    commands = expand_each(args.each, ' '.join(args.commands), cwd) if args.each else list(args.commands)
    if not commands:
        print('getzilla par: no commands to run')
        return 2
    workers = args.jobs or capacity(root)
    started = time.monotonic()
    try:
        jobs, folder = run_batch(root, commands, workers=workers, cwd=cwd, timeout=args.timeout)
    except (OSError, NotImplementedError, AttributeError):
        print('getzilla par: execution or log-ownership backend unavailable; complete_output=false')
        return 1
    print(report(root, jobs, folder, workers=workers, wall=time.monotonic() - started, show_all=args.show_all))
    if any(job.refused for job in jobs):
        return 2
    return 0 if all(job.returncode == 0 for job in jobs) else 1


if __name__ == '__main__':
    raise SystemExit(main())
