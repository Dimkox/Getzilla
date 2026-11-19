"""Opt-in static artifact reconstruction through the existing module lifecycle."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import signal
import stat
import sys
import time
import types

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import fsx  # noqa: E402
from getzilla.continuity import context_binding, scope_gaps  # noqa: E402
from getzilla.execution_output import RESPONSE_BYTES  # noqa: E402
from getzilla.optional_modules import admit_module  # noqa: E402
from getzilla.source_admission import sensitive_class  # noqa: E402
from getzilla.source_secrets import scan_bytes  # noqa: E402
from getzilla.state import require_route_owner  # noqa: E402
from getzilla.util import find_root  # noqa: E402

NAME, VERSION, PERMISSION = 'reverse-engineering', '0.1.0', 'reverse.artifact.read'
MANIFEST_SHA256 = 'fbd153fdd83b6f44645158ca97fe749b730522fe7f6fb308169f3928c8e44b62'
PROVIDER = 'builtin-elf64-le-v1'
MAX_BYTES = 4 * 1024 * 1024


class ReverseError(ValueError):
    """Fixed local refusal code without rejected input or private paths."""


def _need(condition, reason):
    if not condition:
        raise ReverseError(reason)


def _admitted(root):
    admission = admit_module(root, NAME, permission=PERMISSION)
    _need(admission.get('allowed') is True, 'module_disabled_or_missing')
    _need(admission.get('external_authority') is False and admission.get('workers') == 0
          and admission.get('version') == VERSION and admission.get('manifest_sha256') == MANIFEST_SHA256,
          'module_not_qualified')
    return admission


def _task(root):
    try:
        route = require_route_owner(root)
        _need(route.get('status') not in ('completed', 'cancelled') and not scope_gaps(root, route),
              'task_not_ready')
        context = context_binding(root, route)
        _need(context['variant'] == 'package', 'task_package_required')
        return context
    except (OSError, ValueError, KeyError):
        raise ReverseError('task_authority_unavailable') from None


def _load(root, admission):
    """Only exact reviewed provider bytes; project registry cannot select code."""
    prefix = '.getzilla/modules/reverse-engineering/'
    with fsx.ReadOnlyBoundRoot(root) as binding:
        manifest = binding.read(prefix + 'module.json', limit=65536)
        _need(manifest is not None and manifest.sha256 == MANIFEST_SHA256, 'module_not_qualified')
        descriptor = json.loads(manifest.content)
        entry = next(item for item in descriptor['files'] if item['path'] == 'elf.py')
        source = binding.read(prefix + 'elf.py', limit=65536)
        _need(source is not None and source.sha256 == entry['sha256'] and entry['mutable'] is False,
              'module_not_qualified')
        _need(_admitted(root) == admission, 'module_changed')
        module = types.ModuleType('_getzilla_reviewed_reverse_elf')
        # The source-owned manifest pin authenticates these retained provider bytes.
        exec(compile(source.content, '<reviewed-reverse-elf>', 'exec'), module.__dict__)  # nosec B102
        _need(binding.read(prefix + 'elf.py', limit=65536) == source, 'module_changed')
        return module


def _read_artifact(binding, relative, expected):
    _need(type(relative) is str and len(relative) <= 256 and bool(re.fullmatch(r'[A-Za-z0-9_./-]+', relative))
          and all(part not in ('', '.', '..') and not part.startswith('.') for part in relative.split('/')),
          'artifact_path')
    _need(not sensitive_class(relative, allow_examples=False), 'artifact_sensitive_path')
    _need(type(expected) is str and bool(re.fullmatch('[0-9a-f]{64}', expected)), 'artifact_digest')
    try:
        with binding.parent(relative) as (parent, name, check):
            info = fsx.lstat_at(parent, name)
            uid = fsx.effective_uid()
            _need(stat.S_ISREG(info.st_mode) and not fsx.is_link(info) and info.st_nlink == 1
                  and info.st_size <= MAX_BYTES and (uid is None or info.st_uid == uid)
                  and not info.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022), 'artifact_custody')
            check()
        source = binding.read(relative, limit=MAX_BYTES)
        _need(source is not None and source.sha256 == expected, 'artifact_digest')
        findings, unsupported = scan_bytes(relative, source.content)
        _need(not findings and unsupported is None, 'artifact_sensitive_content')
        return source
    except ReverseError:
        raise
    except (OSError, ValueError):
        raise ReverseError('artifact_unavailable') from None


def analyze_project(root, relative, expected_sha256, question, *, provider=PROVIDER,
                    seconds=1.0, max_sections=128, max_functions=128, cancelled=lambda: False):
    # Disabled state checks no source, provider, input or task data.
    admission = _admitted(root)
    _need(type(seconds) in (int, float) and math.isfinite(seconds) and 0 < seconds <= 2, 'invalid_limits')
    started = time.monotonic()
    deadline = started + seconds
    context = _task(root)
    module = _load(root, admission)
    with fsx.ReadOnlyBoundRoot(root) as binding:
        source = _read_artifact(binding, relative, expected_sha256)
        next_check = 0.0

        def stopped():
            nonlocal next_check
            if cancelled():
                return True
            if time.monotonic() >= next_check:
                _need(_admitted(root) == admission and _task(root) == context, 'authority_changed')
                binding.check()
                next_check = time.monotonic() + .05
            return False

        report = module.analyze(source.content, question=question, provider=provider,
                                max_sections=max_sections, max_functions=max_functions,
                                deadline=deadline, cancelled=stopped)
        _need(_admitted(root) == admission and _task(root) == context, 'authority_changed')
        _need(binding.read(relative, limit=MAX_BYTES) == source, 'artifact_changed')
        binding.check()
    result = {'schema_version': 1, 'evidence_authority': False, 'task': context,
              'module_manifest_sha256': MANIFEST_SHA256,
              'artifact': {'path': relative, 'sha256': source.sha256, 'bytes': len(source.content)},
              'analysis': report, 'total_elapsed_seconds': time.monotonic() - started}
    _need(len(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()) <= RESPONSE_BYTES,
          'report_limit')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Optional data-only ELF interface/dependency reconstruction')
    sub = parser.add_subparsers(dest='command', required=True)
    providers = sub.add_parser('providers')
    providers.add_argument('--json', action='store_true')
    analyze = sub.add_parser('analyze')
    analyze.add_argument('artifact')
    analyze.add_argument('--project', type=Path)
    analyze.add_argument('--sha256', required=True)
    analyze.add_argument('--question', required=True)
    analyze.add_argument('--provider', default=PROVIDER)
    analyze.add_argument('--seconds', type=float, default=1.0)
    analyze.add_argument('--max-sections', type=int, default=128)
    analyze.add_argument('--max-functions', type=int, default=128)
    analyze.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    if args.command == 'providers':
        matrix = {PROVIDER: 'static ELF64 LE x86-64 ET_EXEC/ET_DYN; no execution',
                  'ghidra': 'unsupported', 'rea': 'unsupported', 'other_formats': 'unsupported'}
        print(json.dumps(matrix) if args.json else '\n'.join(k + ': ' + v for k, v in matrix.items()))
        return 0
    cancelled = False

    def stop(_number, _frame):
        nonlocal cancelled
        cancelled = True

    old = signal.signal(signal.SIGINT, stop)
    try:
        root = args.project.resolve() if args.project else find_root()
        result = analyze_project(root, args.artifact, args.sha256, args.question,
                                 provider=args.provider, seconds=args.seconds,
                                 max_sections=args.max_sections, max_functions=args.max_functions,
                                 cancelled=lambda: cancelled)
        if args.json:
            print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        else:
            # Render with the same exact admitted provider, never data-selected code.
            print('Artifact: ' + result['artifact']['path'])
            print(_load(root, _admitted(root)).render_text(result['analysis']))
        return 0 if result['analysis']['status'] == 'complete' else 3
    except ReverseError as error:
        print(json.dumps({'status': 'unavailable', 'reason': str(error), 'evidence_authority': False}))
        return 2
    except (OSError, ValueError, KeyError, StopIteration):
        print(json.dumps({'status': 'unavailable', 'reason': 'reverse_unavailable', 'evidence_authority': False}))
        return 2
    finally:
        signal.signal(signal.SIGINT, old)


if __name__ == '__main__':
    raise SystemExit(main())
