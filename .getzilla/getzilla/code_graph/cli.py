"""`getzilla graph`: build, status, impact and export for the Python code graph of one project.

  getzilla graph build  --root DIR [--cache FILE] [--config graph.json]
  getzilla graph status --root DIR [--cache FILE] [--config graph.json]
  getzilla graph impact --root DIR [--cache FILE] [--config graph.json] [--changed PATH ...]
  getzilla graph export --root DIR [--cache FILE]

The project is only read (Git with --no-optional-locks; links are not followed). The only write is
the cache, by default `<root>/.getzilla/index/graph.sqlite`, which is local state outside any source
digest. `impact` does not publish a generation. Output is one JSON document; exit 0 ok, 2 arguments,
3 blocked input, 8 error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from dataclasses import replace
from pathlib import Path
from typing import Any

from ..project_ingestion import _git, route_ingestion
from ..source_models import IngestPolicy, domain_digest
from .builder import build_generation
from .impact import calculate_impact
from .incremental import update_index
from .models import GraphConfig, GraphError, make_graph_input
from .store import DEFAULT_CACHE, GraphStore, build_full_index

LOCAL_STATE = ('.git', '.getzilla/index', '.getzilla/runtime')


def _local_state(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + '/') for prefix in LOCAL_STATE)


def discover_scope(root: Path) -> tuple[Any, dict[str, bytes], dict[str, str]]:
    route = route_ingestion({'path': str(root)}, IngestPolicy())
    if route.route == 'blocked':
        raise GraphError('INPUT_BLOCKED', ','.join(route.reasons))
    scope: dict[str, bytes] = {}
    omitted: dict[str, str] = {}
    if route.route == 'existing_git_baseline':
        listing = _git(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').stdout
        paths = sorted({item.decode('utf-8', 'surrogateescape') for item in listing.split(b'\0') if item})
    else:
        paths = []
        for directory, dirs, names in os.walk(root, followlinks=False):
            relative_dir = Path(directory).relative_to(root).as_posix()
            relative_dir = '' if relative_dir == '.' else relative_dir + '/'
            dirs[:] = sorted(d for d in dirs if not _local_state(relative_dir + d))
            paths.extend(relative_dir + name for name in names)
    for path in sorted(paths):
        if _local_state(path):
            continue
        target = root / path
        try:
            info = target.lstat()
        except FileNotFoundError:
            continue  # tracked but deleted in the working tree
        if not stat.S_ISREG(info.st_mode):
            omitted[path] = 'NOT_A_REGULAR_FILE'
            continue
        scope[path] = target.read_bytes()
    files = [{'path': path, 'sha256': hashlib.sha256(data).hexdigest()} for path, data in sorted(scope.items())]
    scope_digest = domain_digest('getzilla-graph-scope-v1', {'files': files, 'omitted': sorted(omitted.items())})
    if route.baseline is not None:
        # The working-set digest covers exactly the graph scope, so local state (this cache) never makes it stale.
        baseline: Any = replace(route.baseline, working_set_digest=scope_digest)
    else:
        baseline = {'source_kind': 'folder', 'source_digest': scope_digest}
    return baseline, scope, omitted


def _config(path: str | None) -> GraphConfig:
    return GraphConfig() if path is None else GraphConfig.from_dict(json.loads(Path(path).read_text(encoding='utf-8')))


def run(argv: list[str] | None = None) -> tuple[int, dict[str, Any]]:
    parser = argparse.ArgumentParser(prog='getzilla graph', description='Python code graph (read-only)')
    parser.add_argument('command', choices=('build', 'status', 'impact', 'export'))
    parser.add_argument('--root', required=True)
    parser.add_argument('--cache')
    parser.add_argument('--config')
    parser.add_argument('--changed', nargs='*')
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    store = GraphStore(Path(args.cache) if args.cache else root / DEFAULT_CACHE)
    try:
        envelope: dict[str, Any] = {'schema': 'getzilla-graph-cli-v1', 'command': args.command,
                                    'cache_rebuilt_reason': store.rebuilt_reason}
        previous = store.read_active()
        if args.command == 'export':
            envelope['export'] = None if previous is None else previous.export()
            return 0, envelope
        baseline, scope, omitted = discover_scope(root)
        current_input = make_graph_input(baseline, scope, _config(args.config), omitted=omitted)
        if args.command == 'status':
            state = 'missing' if previous is None else (
                'current' if previous.input_identity == current_input.identity else 'stale')
            envelope.update({'status': state, 'input_identity': current_input.identity,
                             'active_generation': None if previous is None else previous.generation_id})
            return 0, envelope
        if args.command == 'build':
            generation = build_full_index(current_input, store) if previous is None else \
                update_index(previous, current_input, store)
            envelope.update({'generation_id': generation.generation_id, 'counters': dict(generation.counters),
                             'coverage': generation.coverage.to_dict()})
            return 0, envelope
        reuse = {} if previous is None or previous.graph_input.get('config') != current_input.config.to_dict() else \
            {(path, item.sha256): item for path, item in previous.parsed.items()}
        current = build_generation(current_input, reuse)
        envelope['impact'] = calculate_impact(previous, current, args.changed).to_dict()
        return 0, envelope
    finally:
        store.close()


def main(argv: list[str] | None = None) -> int:
    try:
        code, envelope = run(argv)
    except GraphError as error:
        code, envelope = 3, {'schema': 'getzilla-graph-cli-v1', 'error': error.reason_code}
    print(json.dumps(envelope, indent=2, sort_keys=True))
    return code
