"""Explicit local design-reference addon; disabled modules load no addon code."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import types
from urllib.parse import quote
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.component_state import BoundRoot  # noqa: E402
from getzilla.continuity import context_binding, scope_gaps  # noqa: E402
from getzilla.fsx import ReadOnlyBoundRoot  # noqa: E402
from getzilla.optional_modules import admit_module, manage_modules, module_status  # noqa: E402
from getzilla.state import require_route_owner, serialized_task  # noqa: E402
from getzilla.util import find_root  # noqa: E402
from getzilla.workflow_storage import change_directory  # noqa: E402

NAME = 'design-reference'
PERMISSION = 'design.reference.read'
MAX_HISTORY = 32
MAX_RECORD_BYTES = 1024 * 1024


class DesignReferenceError(ValueError):
    pass


def _need(condition):
    if not condition:
        raise DesignReferenceError('design_reference_unavailable')


def _encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8', 'strict')


def _load(root, admission):
    """Load only admitted, hash-checked installed bytes, never project imports."""
    prefix = '.getzilla/modules/design-reference/'
    with ReadOnlyBoundRoot(root) as binding:
        descriptor = binding.read(prefix + 'module.json', limit=65536)
        _need(descriptor is not None and descriptor.sha256 == admission['manifest_sha256'])
        manifest = json.loads(descriptor.content)
        _need(manifest['version'] == '0.1.0' and manifest['publisher'] == 'getzilla'
              and manifest['license'] == 'MIT' and manifest['hooks'] == 'declarative-v1')
        entry = next(item for item in manifest['files'] if item['path'] == 'reference.py')
        source = binding.read(prefix + 'reference.py', limit=256 * 1024)
        _need(source is not None and source.sha256 == entry['sha256'] and entry['mutable'] is False)
        _need(admit_module(root, NAME, permission=PERMISSION) == admission)
        module = types.ModuleType('_getzilla_admitted_design_reference')
        exec(compile(source.content, '<admitted-design-reference>', 'exec'), module.__dict__)
        _need(binding.read(prefix + 'reference.py', limit=256 * 1024) == source)
        return module


def _admitted(root):
    admission = admit_module(root, NAME, permission=PERMISSION)
    _need(admission.get('allowed') is True and admission.get('external_authority') is False
          and admission.get('workers') == 0 and admission.get('version') == '0.1.0')
    return admission


def _task(root):
    route = require_route_owner(root)
    _need(not scope_gaps(root, route))
    context = context_binding(root, route)
    _need(context['variant'] == 'package')
    package = change_directory(root, context['change_id'], writable=True)
    _need(package.relative_to(root).as_posix() == context['package_path'])
    return context, context['package_path'] + '/evidence/design-reference'


@serialized_task
def _publish(root, module, pack, admission):
    context, directory = _task(root)
    module.validate_pack(pack)
    record = {'schema_version': 1, 'advisory': True, 'task': context,
              'module_manifest_sha256': admission['manifest_sha256'], 'pack': pack,
              'summary': {'coverage': pack['content']['coverage']['status'],
                          'tokens': len(pack['content']['tokens']),
                          'sources': [row['path'] for row in pack['content']['sources']],
                          'text': 'Local observed tokens: ' + str(len(pack['content']['tokens']))
                          + '; coverage: ' + pack['content']['coverage']['status'] + '.\n'
                          + '\n'.join('[Source ' + str(index) + '](../../../../../../'
                                      + quote(source['path'], safe='/') + ')'
                                      for index, source in enumerate(pack['content']['sources'], 1))
                          + '\nAdvisory only; no functionality, a11y or acceptance claim. D2 remains open.'}}
    raw = _encode(record)
    _need(len(raw) <= MAX_RECORD_BYTES)
    digest = hashlib.sha256(raw).hexdigest()
    relative = directory + '/' + digest + '.json'
    with BoundRoot(root) as binding:
        def current():
            _need(_task(root)[0] == context and _admitted(root) == admission)
            for source in pack['content']['sources']:
                observed = binding.read(source['path'], limit=256 * 1024)
                _need(observed is not None and observed.sha256 == source['sha256'])
            binding.check()
        current()
        existing = binding.read(relative, limit=MAX_RECORD_BYTES)
        if existing is not None:
            _need(existing.content == raw)
            return {'artifact': relative, 'sha256': digest, 'replayed': True, 'advisory': True}
        _need(len(binding.files(directory)) < MAX_HISTORY)
        binding.write(relative, raw, 0o600, expected=None, before_publish=current)
        observed = binding.read(relative, limit=MAX_RECORD_BYTES)
        _need(observed is not None and observed.content == raw)
        return {'artifact': relative, 'sha256': digest, 'replayed': False, 'advisory': True}


def capture(root, files, *, capture_id, captured_at):
    try:
        admission = _admitted(root)  # This must precede all addon loading.
        _task(root)  # No source extraction without the actual owned task package.
        module = _load(root, admission)
        pack = module.capture(root, files, capture_id=capture_id, captured_at=captured_at)
        _need(_admitted(root) == admission)
        return _publish(root, module, pack, admission)
    except (ValueError, OSError, TypeError, KeyError, StopIteration, UnicodeError):
        raise DesignReferenceError('design_reference_unavailable') from None


def compare(root, previous, current):
    try:
        admission = _admitted(root)
        module = _load(root, admission)
        context, directory = _task(root)
        records = []
        with ReadOnlyBoundRoot(root) as binding:
            for digest in (previous, current):
                _need(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest))
                observed = binding.read(directory + '/' + digest + '.json', limit=MAX_RECORD_BYTES)
                _need(observed is not None and observed.sha256 == digest)
                record = json.loads(observed.content)
                _need(set(record) == {'schema_version', 'advisory', 'task', 'module_manifest_sha256', 'pack', 'summary'}
                      and type(record['schema_version']) is int and record['schema_version'] == 1
                      and record['advisory'] is True
                      and all(record['task'][key] == context[key]
                              for key in ('route_id', 'logical_task_id', 'authority_epoch', 'change_id')))
                records.append(record)
        _need(_task(root)[0] == context and _admitted(root) == admission)
        return module.diff(records[0]['pack'], records[1]['pack'])
    except (ValueError, OSError, TypeError, KeyError, StopIteration, UnicodeError):
        raise DesignReferenceError('design_reference_unavailable') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    commands = parser.add_subparsers(dest='operation', required=True)
    for name in ('install', 'update', 'enable', 'disable', 'uninstall', 'status'):
        command = commands.add_parser(name)
        if name in ('install', 'update'):
            command.add_argument('--source', type=Path, default=ROOT)
    command = commands.add_parser('capture')
    command.add_argument('--file', action='append', required=True)
    command.add_argument('--capture-id')
    command.add_argument('--timestamp')
    command = commands.add_parser('diff')
    command.add_argument('previous')
    command.add_argument('current')
    args = parser.parse_args(argv)
    root = args.root if args.root else find_root()
    try:
        if args.operation == 'capture':
            result = capture(root, args.file, capture_id=args.capture_id or uuid.uuid4().hex,
                             captured_at=args.timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
        elif args.operation == 'diff':
            result = compare(root, args.previous, args.current)
        elif args.operation == 'status':
            result = module_status(root)
        else:
            result = manage_modules(root, args.operation,
                                    {NAME: '0.1.0'} if args.operation in ('install', 'update') else {NAME: None},
                                    source=getattr(args, 'source', None),
                                    grants=[PERMISSION] if args.operation == 'enable' else ())
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, TypeError):
        print(json.dumps({'status': 'unavailable', 'reason': 'design_reference_unavailable'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
