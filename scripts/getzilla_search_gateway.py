"""Explicit optional universal search; install and enable never authorize provider calls."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.fsx import ReadOnlyBoundRoot  # noqa: E402
from getzilla.optional_modules import admit_module, manage_modules, module_status, _json  # noqa: E402
from getzilla.util import find_root  # noqa: E402

NAME = 'search-gateway'
VERSION = '0.1.0'
PERMISSION = 'search.web'
EXPECTED_MANIFEST_SHA256 = '82ec96b0c27ebc3d0406a36e1af71bdacd01402d65735e20770a99b8069de0f8'
SOURCES = ('providers.py', 'gateway.py', 'interfaces.py')


def _allowed(root):
    admission = admit_module(root, NAME, permission=PERMISSION)
    return (admission.get('allowed') is True and admission.get('version') == VERSION
            and admission.get('manifest_sha256') == EXPECTED_MANIFEST_SHA256
            and admission.get('external_authority') is False and admission.get('workers') == 0)


def _load(root):
    """Execute only held, immutable, pinned bytes after current module admission."""
    if not _allowed(root):
        raise ValueError('module_unavailable')
    prefix = '.getzilla/modules/search-gateway/'
    with ReadOnlyBoundRoot(root) as binding:
        observed = binding.read(prefix+'module.json', limit=65536)
        if observed is None or observed.sha256 != EXPECTED_MANIFEST_SHA256:
            raise ValueError('module_unavailable')
        manifest = _json(observed.content)
        sources = []
        for name in SOURCES:
            entry = next(item for item in manifest['files'] if item['path'] == name)
            snapshot = binding.read(prefix+name, limit=256*1024)
            if snapshot is None or entry['mutable'] is not False or snapshot.sha256 != entry['sha256']:
                raise ValueError('module_unavailable')
            sources.append((name, snapshot))
        if not _allowed(root):
            raise ValueError('module_unavailable')
        module = types.ModuleType('_getzilla_admitted_search')
        for name, snapshot in sources:
            exec(compile(snapshot.content, '<admitted-search-'+name+'>', 'exec'), module.__dict__)  # nosec B102
        if not _allowed(root) or any(binding.read(prefix+name, limit=256*1024) != snapshot for name,snapshot in sources):
            raise ValueError('module_unavailable')
        return module


def create_gateway(root, config, *, transport=None, clock=None, live_policy=None):
    try:
        root = Path(root).resolve(strict=True)
        if not _allowed(root):
            raise ValueError('module_unavailable')
        module = _load(root)
        config = module.validate_policy(config)
        # Bind the cache's operator scope to this canonical project, independently of caller input.
        config['project'] = hashlib.sha256((str(root)+'\0'+config['project']).encode()).hexdigest()
        return module.Gateway(config, admission=lambda: _allowed(root), transport=transport, clock=clock, live_policy=live_policy)
    except (ValueError, OSError, TypeError, KeyError, StopIteration):
        raise ValueError('search_unavailable') from None


def _private_bytes(path, limit):
    """Read the explicit operator file once; refuse links, broad permissions and oversized files."""
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > limit or info.st_nlink != 1
                or (os.name != 'nt' and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077))
                or path.is_symlink()):
            raise ValueError('operator_file_refused')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(limit+1)
        if len(raw) > limit:
            raise ValueError('operator_file_refused')
        return raw
    finally:
        os.close(descriptor)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    commands = parser.add_subparsers(dest='operation', required=True)
    for name in ('install', 'update', 'enable', 'disable', 'uninstall', 'status'):
        child = commands.add_parser(name)
        if name in ('install', 'update'):
            child.add_argument('--source', type=Path, default=ROOT)
    for name in ('query', 'http', 'mcp-stdio'):
        child = commands.add_parser(name)
        child.add_argument('--policy', type=Path, required=True)
        if name == 'query':
            child.add_argument('--query', required=True)
            child.add_argument('--engine', choices=('auto','google','baidu','yandex'), default='auto')
            child.add_argument('--provider', default='auto')
            child.add_argument('--country')
            child.add_argument('--language')
            child.add_argument('--limit', type=int, default=5)
        if name == 'http':
            child.add_argument('--token-file', type=Path, required=True)
            child.add_argument('--port', type=int, default=8765)
    args = parser.parse_args(argv)
    try:
        root = args.root or find_root()
        if args.operation in ('query', 'http', 'mcp-stdio'):
            # Disabled paths do not open credentials or execute optional sources.
            if not _allowed(root):
                raise ValueError('module_unavailable')
            policy_bytes = _private_bytes(args.policy, 65536)
            config = _json(policy_bytes)
            def current_policy():
                try:
                    return _private_bytes(args.policy, 65536) == policy_bytes
                except (ValueError, OSError):
                    return False
            module = _load(root)
            service = create_gateway(root, config, live_policy=current_policy)
            if args.operation == 'query':
                result = service.web_search({name: getattr(args, name) for name in (
                    'query','engine','provider','country','language','limit') if getattr(args, name) is not None})
            elif args.operation == 'mcp-stdio':
                module.serve_stdio(service, sys.stdin.buffer, sys.stdout.buffer)
                return 0
            else:
                token = _private_bytes(args.token_file, 4096).decode('utf-8').strip()
                server = module.http_server(service, token, port=args.port)
                try:
                    print('Search HTTP listening on 127.0.0.1:'+str(server.server_port), file=sys.stderr, flush=True)
                    server.serve_forever()
                finally:
                    server.server_close()
                return 0
        elif args.operation == 'status':
            result = module_status(root)
        else:
            result = manage_modules(root, args.operation,
                                    {NAME: VERSION} if args.operation in ('install','update') else {NAME: None},
                                    source=getattr(args, 'source', None),
                                    grants=[PERMISSION] if args.operation == 'enable' else ())
        print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 2 if result.get('status') == 'error' else 0
    except KeyboardInterrupt:
        return 130
    except (ValueError, OSError, TypeError, KeyError, UnicodeError):
        # MCP startup failure stays off stdout because it is not a protocol response.
        print(json.dumps({'status':'error','error':'search_unavailable'}),
              file=sys.stderr if args.operation == 'mcp-stdio' else sys.stdout)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
