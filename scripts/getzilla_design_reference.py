"""Explicit local design-reference addon; disabled modules load no addon code."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
import types
from urllib.parse import quote
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import fsx  # noqa: E402
from getzilla.component_state import BoundRoot, _file_identity  # noqa: E402
from getzilla.continuity import context_binding, scope_gaps  # noqa: E402
from getzilla.fsx import ReadOnlyBoundRoot  # noqa: E402
from getzilla.optional_modules import _json as strict_json, admit_module, manage_modules, module_status  # noqa: E402
from getzilla.state import require_route_owner, serialized_task  # noqa: E402
from getzilla.util import find_root  # noqa: E402
from getzilla.workflow_storage import change_directory  # noqa: E402

NAME = 'design-reference'
CURRENT_VERSION = '0.2.0'
PERMISSION = 'design.reference.read'
EXPECTED_MANIFEST_SHA256 = '50609bf8c4137682d170fe0811797089a3dfba5339d94aed196cd4219d82c3e4'
# Read-only compatibility for immutable v1 records from accepted PR368.
HISTORICAL_V1_MANIFEST_SHA256 = '2a8554a1a80dd130d421068fb3ba577cc11fed8b1fbe97025c18442d9c47d452'
TRUSTED_MANIFESTS = {'0.1.0': HISTORICAL_V1_MANIFEST_SHA256, CURRENT_VERSION: EXPECTED_MANIFEST_SHA256}
MAX_HISTORY = 32
MAX_RECORD_BYTES = 1024 * 1024


class DesignReferenceError(ValueError):
    pass


def _need(condition, reason='design_reference_unavailable'):
    if not condition:
        raise DesignReferenceError(reason)


def _encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('utf-8', 'strict')


def _load(root, admission, *, entrypoint='reference.py'):
    """Load only admitted, hash-checked installed bytes, never project imports."""
    _need(entrypoint in ('reference.py', 'preview.py')
          and (entrypoint == 'reference.py' or admission['version'] == CURRENT_VERSION))
    prefix = '.getzilla/modules/design-reference/'
    with ReadOnlyBoundRoot(root) as binding:
        descriptor = binding.read(prefix + 'module.json', limit=65536)
        _need(descriptor is not None and descriptor.sha256 == admission['manifest_sha256'])
        manifest = json.loads(descriptor.content)
        _need(manifest['version'] == admission['version'] and manifest['publisher'] == 'getzilla'
              and manifest['license'] == 'MIT' and manifest['hooks'] == 'declarative-v1')
        entry = next(item for item in manifest['files'] if item['path'] == entrypoint)
        source = binding.read(prefix + entrypoint, limit=256 * 1024)
        _need(source is not None and source.sha256 == entry['sha256'] and entry['mutable'] is False)
        _need(admit_module(root, NAME, permission=PERMISSION) == admission)
        module = types.ModuleType('_getzilla_admitted_design_reference')
        # Fixed reviewed manifest pins these held immutable source bytes.
        exec(compile(source.content, '<admitted-design-reference>', 'exec'), module.__dict__)  # nosec B102
        _need(binding.read(prefix + entrypoint, limit=256 * 1024) == source)
        return module


def _admitted(root):
    admission = admit_module(root, NAME, permission=PERMISSION)
    _need(admission.get('allowed') is True and admission.get('external_authority') is False
          and admission.get('workers') == 0 and admission.get('version') in TRUSTED_MANIFESTS
          and admission.get('manifest_sha256') == TRUSTED_MANIFESTS[admission['version']])
    return admission


def _task(root):
    route = require_route_owner(root)
    _need(not scope_gaps(root, route))
    context = context_binding(root, route)
    _need(context['variant'] == 'package')
    package = change_directory(root, context['change_id'], writable=True)
    _need(package.relative_to(root).as_posix() == context['package_path'])
    return context, context['package_path'] + '/evidence/design-reference'


def _record(context, pack, admission):
    if pack['content']['schema_version'] == 2:
        return {'schema_version': 1, 'advisory': True, 'task': context,
                'module_manifest_sha256': admission['manifest_sha256'], 'pack': pack,
                'summary': {'coverage': 'partial', 'tokens': len(pack['content']['tokens']),
                            'sources': [row['path'] for row in pack['content']['sources']],
                            'text': 'Controlled fixture computed styles; partial coverage.\n'
                            + '\n'.join('[Fixture source](' + quote(row['path'], safe='/:?=&%') + ')'
                                        for row in pack['content']['sources'])
                            + '\nAdvisory only; no functionality, a11y, acceptance or live passivity claim.'}}
    return {'schema_version': 1, 'advisory': True, 'task': context,
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


def _history_paths(binding, directory):
    paths = []
    try:
        with binding.parent(directory + '/.inventory') as (parent, _name, check):
            with fsx.scandir(parent) as entries:
                for entry in entries:
                    _need(len(paths) < MAX_HISTORY, 'design_reference_capacity')
                    _need(re.fullmatch('[0-9a-f]{64}\\.json', entry.name))
                    paths.append(directory + '/' + entry.name)
            check()
    except FileNotFoundError:
        return []
    return sorted(paths)


def _record_identity(binding, relative):
    with binding.parent(relative) as (parent, name, check):
        info = fsx.lstat_at(parent, name)
        uid = fsx.effective_uid()
        _need(stat.S_ISREG(info.st_mode) and not fsx.is_link(info) and info.st_nlink == 1
              and info.st_size <= MAX_RECORD_BYTES and (uid is None or info.st_uid == uid))
        if not fsx.WINDOWS:
            _need(stat.S_IMODE(info.st_mode) & 0o077 == 0)
        check()
        return _file_identity(info)


def _history(binding, directory, module, context, admission):
    records, ids = {}, set()
    for relative in _history_paths(binding, directory):
        identity = _record_identity(binding, relative)
        observed = binding.read(relative, limit=MAX_RECORD_BYTES)
        _need(observed is not None and observed.identity == identity
              and observed.sha256 + '.json' == relative.rsplit('/', 1)[1])
        record = strict_json(observed.content)
        _need(type(record) is dict and set(record) == {'schema_version', 'advisory', 'task', 'module_manifest_sha256', 'pack', 'summary'})
        task = record['task']
        _need(type(task) is dict and set(task) == set(context)
              and all(task[key] == context[key] and type(task[key]) is type(context[key])
                      for key in ('version', 'route_id', 'logical_task_id', 'change_id', 'variant', 'package_path'))
              and type(task['authority_epoch']) is int and 0 <= task['authority_epoch'] <= context['authority_epoch']
              and type(task['context_revision']) is int and task['context_revision'] >= 0
              and (task['authority_epoch'] < context['authority_epoch']
                   or task['context_revision'] <= context['context_revision'])
              and all(type(task[key]) is str and re.fullmatch('[0-9a-f]{64}', task[key])
                      for key in ('spec_digest', 'requirements_digest', 'digest'))
              and task['digest'] == hashlib.sha256(_encode({key: value for key, value in task.items() if key != 'digest'})).hexdigest())
        module.validate_pack(record['pack'])
        historical = record['module_manifest_sha256']
        _need(historical == admission['manifest_sha256'] or
              (historical == HISTORICAL_V1_MANIFEST_SHA256 and record['pack']['content']['schema_version'] == 1))
        historical_admission = dict(admission, manifest_sha256=historical)
        _need(_encode(record) == observed.content == _encode(_record(task, record['pack'], historical_admission)))
        identity = record['pack']['capture']['id']
        _need(identity not in ids)
        ids.add(identity)
        records[relative] = (observed, record)
    return records


@serialized_task
def _publish(root, module, pack, admission):
    context, directory = _task(root)
    module.validate_pack(pack)
    record = _record(context, pack, admission)
    raw = _encode(record)
    _need(len(raw) <= MAX_RECORD_BYTES)
    digest = hashlib.sha256(raw).hexdigest()
    relative = directory + '/' + digest + '.json'
    with BoundRoot(root) as binding:
        history = _history(binding, directory, module, context, admission)
        paths = sorted(history)
        def current():
            _need(_task(root)[0] == context and _admitted(root) == admission)
            for path, (snapshot, _record_value) in history.items():
                _need(_record_identity(binding, path) == snapshot.identity)
            # The existing writer owns a private staging leaf in this directory.
            # Do not classify that transient leaf as a new history record.
            try:
                identity = _record_identity(binding, relative)
            except FileNotFoundError:
                identity = None
            if identity is not None:
                existing = binding.read(relative, limit=MAX_RECORD_BYTES)
                _need(existing is not None and existing.identity == identity and existing.content == raw)
            for source in (pack['content']['sources'] if pack['content']['schema_version'] == 1 else []):
                observed = binding.read(source['path'], limit=256 * 1024)
                _need(observed is not None and observed.sha256 == source['sha256'])
            binding.check()
        current()
        for existing, previous in history.values():
            if previous['pack']['capture']['id'] == pack['capture']['id']:
                _need(existing.content == raw, 'design_reference_id_conflict')
                return {'artifact': relative, 'sha256': digest, 'replayed': True, 'advisory': True}
        _need(len(paths) < MAX_HISTORY, 'design_reference_capacity')
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
    except DesignReferenceError:
        raise
    except (ValueError, OSError, TypeError, KeyError, StopIteration, UnicodeError):
        raise DesignReferenceError('design_reference_unavailable') from None


def capture_preview(root, url, resources, *, capture_id, captured_at, viewport=None, theme='light', locale='en-US'):
    try:
        admission = _admitted(root)
        _need(admission['version'] == CURRENT_VERSION)  # Legacy local authority never enables preview.
        _task(root)
        module = _load(root, admission)
        adapter = _load(root, admission, entrypoint='preview.py')
        pack = adapter.capture_preview(module, url, resources, capture_id=capture_id, captured_at=captured_at,
                                      viewport=viewport, theme=theme, locale=locale)
        _need(_admitted(root) == admission)
        return _publish(root, module, pack, admission)
    except DesignReferenceError:
        raise
    except (ValueError, OSError, TypeError, KeyError, StopIteration, UnicodeError):
        raise DesignReferenceError('design_reference_unavailable') from None


def compare(root, previous, current):
    try:
        admission = _admitted(root)
        module = _load(root, admission)
        context, directory = _task(root)
        records = []
        with ReadOnlyBoundRoot(root) as binding:
            history = _history(binding, directory, module, context, admission)
            for digest in (previous, current):
                _need(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest))
                relative = directory + '/' + digest + '.json'
                _need(relative in history)
                records.append(history[relative][1])
        _need(_task(root)[0] == context and _admitted(root) == admission)
        return module.diff(records[0]['pack'], records[1]['pack'])
    except DesignReferenceError:
        raise
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
    command = commands.add_parser('capture-preview-fixture')
    command.add_argument('--url', required=True)
    command.add_argument('--resource', action='append', required=True)
    command.add_argument('--width', type=int, default=1280)
    command.add_argument('--height', type=int, default=720)
    command.add_argument('--theme', choices=('light', 'dark'), default='light')
    command.add_argument('--locale', default='en-US')
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
        elif args.operation == 'capture-preview-fixture':
            result = capture_preview(root, args.url, sorted(set(args.resource)),
                                     capture_id=args.capture_id or uuid.uuid4().hex,
                                     captured_at=args.timestamp or datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                                     viewport={'width': args.width, 'height': args.height},
                                     theme=args.theme, locale=args.locale)
        elif args.operation == 'diff':
            result = compare(root, args.previous, args.current)
        elif args.operation == 'status':
            result = module_status(root)
        else:
            result = manage_modules(root, args.operation,
                                    {NAME: CURRENT_VERSION} if args.operation in ('install', 'update') else {NAME: None},
                                    source=getattr(args, 'source', None),
                                    grants=[PERMISSION] if args.operation == 'enable' else ())
        print(json.dumps(result, sort_keys=True))
        return 0
    except DesignReferenceError as error:
        args = BaseException.args.__get__(error, type(error))
        reason = args[0] if len(args) == 1 and type(args[0]) is str and args[0] in {
            'design_reference_capacity', 'design_reference_id_conflict'} else 'design_reference_unavailable'
        print(json.dumps({'status': 'unavailable', 'reason': reason}))
        return 2
    except (ValueError, OSError, TypeError):
        print(json.dumps({'status': 'unavailable', 'reason': 'design_reference_unavailable'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
