#!/usr/bin/env python3
"""Dispatch legacy root hooks into the canonical installation.

Mandatory PreToolUse cannot fall back to allow. Optional lifecycle hooks keep
an empty observation when their canonical script is absent.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
import runpy
import sys
from pathlib import Path

NAME = Path(__file__).name
ROOT = Path(__file__).resolve().parent


def _reject() -> None:
    reason = 'Mandatory Getzilla hook unavailable or failed.'
    specific = {'hookEventName': 'PreToolUse', 'permissionDecision': 'deny',
                'permissionDecisionReason': reason}
    args = sys.argv[1:]
    harness = args[args.index('--harness') + 1] if '--harness' in args and args.index('--harness') + 1 < len(args) else 'grok'
    if harness in {'claude', 'codex', 'qwen'}:
        output = {'hookSpecificOutput': specific}
    elif harness == 'copilot':
        output = {'permissionDecision': 'deny', 'permissionDecisionReason': reason}
    else:
        output = {'decision': 'deny', 'reason': reason}
        if harness == 'grok':
            output['hookSpecificOutput'] = specific
    sys.stdout.write(json.dumps(output) + '\n')
    raise SystemExit(2)


def main(name: str = NAME, root: Path = ROOT) -> None:
    canonical = root / '.grok' / 'hooks' / name
    mandatory = name == 'pre_tool_use.py'
    if not canonical.is_file():
        if mandatory:
            _reject()
        sys.stdout.write('{}\n')
        return
    hook_dir = str(canonical.parent)
    if hook_dir not in sys.path:
        sys.path.insert(0, hook_dir)
    sys.argv[0] = str(canonical)
    if not mandatory:
        runpy.run_path(str(canonical), run_name='__main__')
        return
    # Do not let a partial allow survive a bootstrap or evaluation exception.
    output = io.StringIO()
    try:
        with redirect_stdout(output):
            runpy.run_path(str(canonical), run_name='__main__')
    except BaseException:
        _reject()
    sys.stdout.write(output.getvalue())


if __name__ == '__main__':
    main()
