"""Run unittest once and report its actual collection result across Python versions."""
from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import unittest


def _journal_observer():
    if not os.environ.get('GETZILLA_JOURNAL_DIR'):
        return None, None
    created = []
    try:
        run = os.environ.get('GETZILLA_JOURNAL_RUN', '')
        if (not re.fullmatch('[0-9a-f]{32}', run)
                or not re.fullmatch('[0-9a-f]{32}', os.environ.get('GETZILLA_JOURNAL_NONCE', ''))
                or not re.fullmatch(r'(?:[0-9]|[1-5][0-9]|6[0-3])', os.environ.get('GETZILLA_JOURNAL_ACTOR', ''))
                or not Path(os.environ['GETZILLA_JOURNAL_DIR']).is_absolute()):
            raise ValueError('unavailable observer context')
        name = '_getzilla_observer_' + run
        if any(key == name or key.startswith(name + '.') for key in sys.modules):
            raise ValueError('observer namespace exists')
        sdk = Path(__file__).resolve().parents[1] / '.getzilla'
        archive = sdk / 'getzilla.zip'
        paths = ([str(archive / 'getzilla')] if archive.is_file() else []) + [str(sdk / 'getzilla')]
        spec = importlib.machinery.ModuleSpec(name, None, is_package=True)
        spec.submodule_search_locations = paths
        package = importlib.util.module_from_spec(spec)
        sys.modules[name] = package
        created.append((name, package))
        for leaf in ('fsx', 'verification_journal'):
            identity = name + '.' + leaf
            spec = importlib.machinery.PathFinder.find_spec(identity, paths)
            if spec is None or spec.loader is None:
                raise ImportError('observer source unavailable')
            module = importlib.util.module_from_spec(spec)
            sys.modules[identity] = module
            created.append((identity, module))
            spec.loader.exec_module(module)
            setattr(package, leaf, module)
        diagnostics = package.verification_journal
        writer = diagnostics.child_writer()
        if writer is None:
            raise ValueError('observer context unavailable')
        return diagnostics, writer
    except Exception:
        for identity, module in reversed(created):
            if sys.modules.get(identity) is module:
                del sys.modules[identity]
        print('getzilla journal: observer unavailable', file=sys.stderr, flush=True)
        return None, None


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--result', type=Path)
    parser.add_argument('--nonce')
    parser.add_argument('--journal-only', action='store_true')
    options, arguments = parser.parse_known_args()
    if not options.journal_only and (options.result is None or options.nonce is None):
        parser.error('result and nonce required')
    diagnostics, writer = _journal_observer()
    try:
        if writer:
            writer.emit('collection', 'start')
        program = unittest.main(module=None, argv=[sys.argv[0], *arguments], exit=False,
                                testRunner=diagnostics.unittest_runner(writer) if writer else None)
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                print('getzilla journal: observer unavailable', file=sys.stderr, flush=True)
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
