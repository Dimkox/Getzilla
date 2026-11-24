"""Native bounded Linux execution: start a pinned tool, get, wait or cancel."""

from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".getzilla"))
from getzilla import execution, execution_store, supervised_execution as backend
from getzilla.util import find_root


class Parser(argparse.ArgumentParser):
    def error(self, message):
        print(json.dumps({"error": "invalid_arguments"}))
        raise SystemExit(2)


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == ["--supervisor"]:
        try:
            backend.supervise()
            return 0
        except (OSError, ValueError, KeyError, TypeError):
            return 2
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("start")
    start.add_argument("--tool", required=True)
    start.add_argument("--intent", required=True)
    start.add_argument("--timeout", type=int, required=True)
    for name in ("get", "wait", "cancel"):
        sub = commands.add_parser(name)
        sub.add_argument("execution_id")
        if name == "wait":
            sub.add_argument("--seconds", type=float, default=1)
    args = parser.parse_args(arguments)
    root = find_root()
    try:
        if args.command == "start":
            result = backend.start(root, tool_id=args.tool, intent_key=args.intent, hard_timeout_seconds=args.timeout)
        elif args.command == "cancel":
            result = backend.cancel(root, args.execution_id)
        else:
            result = backend.observe(
                root, args.execution_id, wait_seconds=args.seconds if args.command == "wait" else None
            )
    except (execution.ExecutionError, execution_store.RegistryError) as error:
        print(json.dumps({"error": error.code}))
        return 2
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"error": "execution_unavailable"}))
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
