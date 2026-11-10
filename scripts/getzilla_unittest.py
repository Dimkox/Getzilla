"""Run unittest once and report its actual collection result across Python versions."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla import verification_journal as diagnostics


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--result', type=Path)
    parser.add_argument('--nonce')
    parser.add_argument('--journal-only', action='store_true')
    options, arguments = parser.parse_known_args()
    if not options.journal_only and (options.result is None or options.nonce is None):
        parser.error('result and nonce required')
    writer = diagnostics.child_writer()
    try:
        if writer:
            writer.emit('collection', 'start')
        program = unittest.main(module=None, argv=[sys.argv[0], *arguments], exit=False,
                                testRunner=diagnostics.unittest_runner(writer) if writer else None)
    finally:
        if writer:
            writer.close()
    result = program.result
    # The parent supplies a fresh path in its private invocation directory.
    # A premature native exit leaves no report and cannot qualify as success.
    if not options.journal_only:
        descriptor = os.open(options.result, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
            json.dump({'schema_version': 1, 'nonce': options.nonce, 'tests_run': result.testsRun,
                       'successful': result.wasSuccessful()}, output)
    if result.testsRun == 0:
        return 5
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
