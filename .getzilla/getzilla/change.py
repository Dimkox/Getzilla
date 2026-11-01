from __future__ import annotations

import json
import os
import secrets
import shutil
from pathlib import Path
from typing import Any

from .package_status import collect_worktree, read_package_file
from .state import (get_active_route, set_active_change, update_route, serialized_task,
                    require_route_owner, durable_json, durable_bytes, _safe_parents)
from .spec import dump_canonical_spec, generate_spec
from .util import dump_json, now_utc
from .workflow_storage import change_directory

GOVERNANCE_AUTHORITY_NOTICE = (
    "Canonical governance JSON under `governance/` remains separately reviewed "
    "authority. Any rule, example, debt, or digest named here is non-authoritative "
    "context until the verifier rederives current governance evidence."
)

def public_change_slug(title: str) -> str:
    """Keep public paths independent of task text; date and route identify the change."""
    return "task"

TRANSITIONS = {
    'draft': {'scoped', 'cancelled'},
    'scoped': {'approved', 'draft', 'cancelled'},
    'approved': {'implementing', 'cancelled'},
    'implementing': {'verifying', 'blocked', 'cancelled'},
    'blocked': {'implementing', 'cancelled'},
    'verifying': {'reviewing', 'implementing', 'blocked'},
    'reviewing': {'ready', 'implementing', 'blocked'},
    'ready': {'released', 'implementing'},
    'released': {'archived'},
    'archived': set(),
    'cancelled': set(),
}


def _checkpoint(root: Path, route: dict[str, Any], change_id: str, kind: str) -> dict[str, Any]:
    observation = collect_worktree(root, route)
    return {
        'kind': kind,
        'change_id': change_id,
        'route_id': route['route_id'],
        'observed_at': observation['observed_at'],
        'branch': observation['branch'],
        'head': observation['head'],
        'detached': observation['detached'],
        'git_available': observation['git_available'],
        'git_findings': [item['code'] for item in observation['findings']],
        'dirty_product_state': observation['dirty_product_state'],
        'dirty_product_paths': observation['dirty_product_paths'],
        'note': 'draft; implementation not started' if kind == 'initial' else 'implementation started; preserve work before handoff',
    }


def _mirror_checkpoints(root: Path, path: Path, state: dict[str, Any]) -> None:
    """State is canonical; a failed README write is explicit and retryable."""
    if not state.get('checkpoint_mirror_pending'):
        return
    readme = path / 'evidence/README.md'
    content = read_package_file(root, readme.relative_to(root).as_posix()).decode('utf-8', 'strict')
    for checkpoint in state.get('checkpoints', []):
        marker = f"<!-- checkpoint:{checkpoint['kind']} -->"
        if marker in content:
            continue
        content += f"\n{marker}\n## {checkpoint['kind'].capitalize()} checkpoint\n\n"
        content += 'Local observation only; not verification or publication evidence.\n\n'
        content += '```json\n' + json.dumps(checkpoint, ensure_ascii=True, indent=2) + '\n```\n'
        if checkpoint['kind'] == 'initial':
            content += '\nInitial evidence accounting (current records are in `state.json`):\n\n```json\n'
            content += json.dumps(state['evidence_accounting'], ensure_ascii=True, indent=2) + '\n```\n'
    durable_bytes(root, readme, content.encode('utf-8'))
    state['checkpoint_mirror_pending'] = False
    durable_json(root, path / 'state.json', state)


@serialized_task
def start_change(root: Path, title: str | None = None) -> dict[str, Any]:
    from .continuity import normalize_route, attach_package
    from . import fsx
    route = get_active_route(root)
    if not route:
        raise RuntimeError('No active route. Submit a development task or run scripts/getzilla_route.py first.')
    route = normalize_route(root, route)
    title = title or route['task']
    change_id = f"{route['created_at'][:10].replace('-', '')}-{public_change_slug(title)}-{route['route_id'][:6]}"
    path = change_directory(root, change_id, writable=True)
    if path.exists():
        state = _complete_package(root, path, route, change_id)
        attach_package(root, route, change_id, path)
        _mirror_checkpoints(root, path, state)
        return state
    handles, _ = _safe_parents(root, path.parent.relative_to(root))
    staging_name = '.creating-' + secrets.token_hex(16)
    staging = path.parent / staging_name
    try:
        fsx.mkdir_at(handles[-1], staging_name, 0o700)
        state = _create_package(root, staging, route, change_id, title)
        _complete_package(root, staging, route, change_id)
        for directory, _, names in os.walk(staging, topdown=False):
            for name in names:
                read_package_file(root, (Path(directory) / name).relative_to(root).as_posix(),
                                  limit=1_048_576 if name == 'route.json' else 262_144, sync=True)
            handle = fsx.open_dir(directory)
            try:
                fsx.fsync_dir(handle)
            finally:
                fsx.close_dir(handle)
        from .workflow_artifacts import _rename_noreplace
        _rename_noreplace(handles[-1], staging_name, path.name)
        fsx.fsync_dir(handles[-1])
    finally:
        for handle in reversed(handles):
            fsx.close_dir(handle)
        # Interrupted staging is intentionally retained for diagnosis, never accepted as complete.
    attach_package(root, route, change_id, path)
    _mirror_checkpoints(root, path, state)
    return state


def _complete_package(root: Path, path: Path, route: dict[str, Any], change_id: str) -> dict[str, Any]:
    from .state import _route_document
    from .package_status import PACKAGE_MARKDOWN
    from .spec import _parse_canonical_json, _validate_document
    value = _route_document(root, path / 'state.json')
    if value.get('change_id') != change_id or value.get('route_id') != route['route_id'] or not value.get('status'):
        raise ValueError('existing package is partial or conflicts with the task; preserve it and diagnose')
    spec = _parse_canonical_json(read_package_file(root, (path / 'change-spec.yaml').relative_to(root).as_posix()),
                                 path / 'change-spec.yaml')
    _validate_document(spec, gate=False, root=root)
    if spec.get('change_id') != change_id:
        raise ValueError('existing package spec identity conflicts with the task')
    for name in PACKAGE_MARKDOWN:
        read_package_file(root, (path / name).relative_to(root).as_posix()).decode('utf-8', 'strict')
    return value


def _create_package(root: Path, path: Path, route: dict[str, Any], change_id: str, title: str) -> dict[str, Any]:
    template = root / '.getzilla/templates/change'
    if any(item.is_symlink() for item in template.rglob('*')):
        raise ValueError('unsafe change template')
    shutil.copytree(template, path, dirs_exist_ok=True)
    generated_route = {**route, 'change_id': change_id}
    if len(route['task']) > 4096:
        generated_route['task'] = 'UNRESOLVED: explicitly map the complete original from the canonical route into bounded typed criteria.'
    (path / 'change-spec.yaml').write_text(
        dump_canonical_spec(generate_spec(generated_route)),
        encoding='utf-8',
        newline='\n',
    )
    replacements = {
        '{{CHANGE_ID}}': change_id,
        '{{TITLE}}': title,
        '{{TASK}}': route['task'],
        '{{CREATED_AT}}': now_utc(),
        '{{RISK}}': route['risk'],
        '{{COMPLEXITY}}': route['complexity'],
        '{{DOMAINS}}': ', '.join(route['domains']),
        '{{GOVERNANCE_AUTHORITY_NOTICE}}': GOVERNANCE_AUTHORITY_NOTICE,
    }
    for file in path.rglob('*'):
        if file.is_file():
            if file.name == 'change-spec.yaml':
                continue
            try:
                content = file.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                continue
            for key, value in replacements.items():
                content = content.replace(key, str(value))
            file.write_text(content, encoding='utf-8', newline='\n')
    dump_json(path / 'route.json', route)
    from .human_gates import route_gate_digest

    human_gates = route.get('human_gates', [])
    state = {
        'schema_version': 1,
        'change_id': change_id,
        'title': title,
        'route_id': route['route_id'],
        'human_gates': human_gates,
        'human_gates_digest': route_gate_digest(route['route_id'], human_gates),
        'status': 'draft',
        'created_at': now_utc(),
        'updated_at': now_utc(),
        'history': [{'from': None, 'to': 'draft', 'at': now_utc(), 'reason': 'created'}],
        'checkpoints': [_checkpoint(root, route, change_id, 'initial')],
        'checkpoint_mirror_pending': True,
        'evidence_accounting': {
            'schema_version': 1,
            'obligations': [
                {'id': kind, 'kind': 'receipt', 'receipt_kind': kind, 'status': 'not_run', 'reason': 'implementation not started'}
                for kind in route.get('required_evidence', [])
            ],
        },
    }
    durable_json(root, path / 'state.json', state)
    return state


@serialized_task
def transition(root: Path, change_id: str, target: str, reason: str) -> dict[str, Any]:
    from .continuity import normalize_route, scope_gaps
    route = normalize_route(root)
    require_route_owner(root, route)
    if route.get('change_id') != change_id:
        raise ValueError('package transition requires its canonical task owner')
    if target in {'verifying', 'reviewing', 'ready', 'released'}:
        gaps = scope_gaps(root, route)
        if gaps:
            raise ValueError('; '.join(gaps))
    package = change_directory(root, change_id, writable=True)
    path = package / 'state.json'
    if not path.is_file():
        raise FileNotFoundError(path)
    state = json.loads(path.read_text(encoding='utf-8'))
    set_active_change(root, {'change_id': change_id, 'path': package.relative_to(root).as_posix()})
    current = state['status']
    if target == current and state.get('checkpoint_mirror_pending'):
        _mirror_checkpoints(root, path.parent, state)
        update_route(root, status=target)
        return state
    if target not in TRANSITIONS.get(current, set()):
        raise ValueError(f'Invalid transition {current} -> {target}')
    from .human_gates import gate_transition_block_reason, open_gate_flags

    gate_reason = gate_transition_block_reason(root, target, change_id)
    if gate_reason:
        raise ValueError(gate_reason)
    open_gates = open_gate_flags(root)
    if target == 'implementing' and not any(row.get('kind') == 'implementation' for row in state.get('checkpoints', [])):
        route = get_active_route(root) or {'route_id': state.get('route_id')}
        state.setdefault('checkpoints', []).append(_checkpoint(root, route, change_id, 'implementation'))
        state['checkpoint_mirror_pending'] = True
    state['status'] = target
    state['updated_at'] = now_utc()
    entry = {'from': current, 'to': target, 'at': now_utc(), 'reason': reason}
    if open_gates:
        entry['open_human_gates'] = open_gates  # flags: shown, never enforced
    state.setdefault('history', []).append(entry)
    dump_json(path, state)
    _mirror_checkpoints(root, path.parent, state)
    update_route(root, status=target)
    return state
