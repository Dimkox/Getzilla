#!/usr/bin/env python3
"""Components a project gets when it needs them, from the same local Getzilla version.

  getzilla components status [--project DIR]
  getzilla components add agent:<name>|factory|compliance:eu-ai-act|extra:bitrix|extra:seo-landing [--project DIR]
  getzilla components adopt --agents 'qwen,codex'  (complete legacy selection; '' selects none)

Existing files are never overwritten; additions are recorded in .getzilla/managed-components.json.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.on_demand import adopt_selection, ensure_components, find_installed_project, is_installed_project, is_source_checkout, getzilla_home  # noqa: E402
from getzilla.component_state import parse_agents, read_state  # noqa: E402
from dataclasses import asdict
from getzilla.module_runtime import quiesce_module
from getzilla.optional_modules import (  # noqa: E402
    REGISTRY, ModuleError, load_registry, module_status, plan_modules, manage_modules,
    recover_modules, rollback_modules,
)


def _module_command(args, project):
    if args.operation == 'registry':
        source = args.source or (ROOT if is_source_checkout(ROOT) else getzilla_home())
        registry = load_registry(source, args.registry)
        return {'registry_sha256': registry.sha256, **registry.data}
    if args.operation == 'status':
        return module_status(project)
    if args.operation in {'recover', 'rollback'}:
        if args.modules or args.plan:
            raise ModuleError('recovery_takes_no_module_requests')
        return recover_modules(project) if args.operation == 'recover' else rollback_modules(project)
    requests = {}
    for item in args.modules:
        name, separator, version = item.partition('@')
        if name in requests:
            raise ModuleError('duplicate_module_request')
        requests[name] = version if separator else None
    if args.operation == 'quiesce':
        if len(requests) != 1 or args.plan or args.grant or any(v is not None for v in requests.values()):
            raise ModuleError('quiesce_requires_one_installed_module')
        # No qualified resource-service port is composed by this standalone CLI.
        # It durably denies new work and reports unavailable; it never claims teardown.
        return asdict(quiesce_module(project, next(iter(requests))))
    source = args.source
    if args.operation in {'install', 'update'} and source is None:
        source = ROOT if is_source_checkout(ROOT) else getzilla_home()
    function = plan_modules if args.plan else manage_modules
    return function(project, args.operation, requests, source=source, registry_path=args.registry, grants=args.grant)



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='getzilla components', description=__doc__.split('\n')[0])
    sub = parser.add_subparsers(dest='command')
    status = sub.add_parser('status')
    status.add_argument('--project', type=Path)
    add = sub.add_parser('add')
    add.add_argument('components', nargs='+')
    add.add_argument('--project', type=Path)
    adopt = sub.add_parser('adopt', help='Record a complete legacy selection without changing adapter files.')
    adopt.add_argument('--agents', required=True)
    module = sub.add_parser('module', help='Explicit optional module lifecycle; no addon runs during these commands.')
    module.add_argument('operation', choices=('registry', 'status', 'install', 'update', 'enable', 'disable', 'uninstall', 'recover', 'rollback', 'quiesce'))
    module.add_argument('modules', nargs='*', help='exact id@version for install/update; installed id for other operations')
    module.add_argument('--project', type=Path)
    module.add_argument('--source', type=Path)
    module.add_argument('--registry', default=REGISTRY)
    module.add_argument('--grant', action='append', default=[])
    module.add_argument('--plan', action='store_true')
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    try:
        if args.command == 'module' and args.operation == 'registry':
            print(json.dumps(_module_command(args, None), indent=2, sort_keys=True))
            return 0
        explicit = getattr(args, 'project', None)
        project = explicit.absolute() if explicit is not None else find_installed_project(Path.cwd())
        if project is None or not is_installed_project(project):
            raise ValueError(f'{explicit or Path.cwd()} is not a project Getzilla was installed into')
        if args.command == 'module':
            print(json.dumps(_module_command(args, project), indent=2, sort_keys=True))
            return 0
        if args.command == 'status':
            state = read_state(project)
            print(json.dumps({'selection_state': state.kind, **state.manifest}, indent=2, sort_keys=True))
            return 0
        if args.command == 'adopt':
            manifest = adopt_selection(project, parse_agents(args.agents))
            print(json.dumps({'ok': True, 'selection_state': 'selected', **manifest}, indent=2, sort_keys=True))
            return 0
        results = ensure_components(project, list(args.components), source=ROOT if is_source_checkout(ROOT) else getzilla_home())
    except (ValueError, OSError) as error:
        print(json.dumps({'ok': False, 'error': str(error)}))
        return 2
    print(json.dumps({'ok': True, 'added': [item.to_dict() for item in results]}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
