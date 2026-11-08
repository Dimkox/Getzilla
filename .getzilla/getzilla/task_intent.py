"""Bounded semantic questions in the canonical task; records confer no authority."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from . import state

MAX_QUESTIONS = 32
MAX_OPERATIONS = 128
MAX_INTENT_BYTES = 131_072
_ID = re.compile(r'[A-Za-z0-9_.:/-]{1,128}\Z')
_HEX = re.compile(r'[0-9a-f]{64}\Z')
NOTICE = 'Local human-response provenance, not authenticated identity, delegated grant or acceptance evidence.'


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _identifier(value: Any) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _text(value: Any, maximum: int = 4096) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value.encode('utf-8')) <= maximum


def _path(value: Any) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= 512 and not value.startswith('/') and
            not any(char in value for char in '\\:*?[]\0\r\n') and
            all(part not in {'', '.', '..', '.git'} for part in (value[:-1] if value.endswith('/') else value).split('/')))


def _question(value: Any, *, stored: bool) -> None:
    keys = {'id', 'question', 'targets', 'paths', 'source_ref'}
    if stored:
        keys |= {'opened_digest', 'answer'}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('invalid closed intent question')
    if not _identifier(value['id']) or not _text(value['question']) or not _text(value['source_ref'], 1024):
        raise ValueError('invalid intent question identity, text or source')
    targets, paths = value['targets'], value['paths']
    if (not isinstance(targets, list) or not 1 <= len(targets) <= 32 or
            any(not _identifier(item) for item in targets) or len(set(targets)) != len(targets) or
            not isinstance(paths, list) or len(paths) > 64 or any(not _path(item) for item in paths) or
            len(set(paths)) != len(paths)):
        raise ValueError('invalid intent targets or affected paths')
    if stored:
        if not isinstance(value['opened_digest'], str) or not _HEX.fullmatch(value['opened_digest']):
            raise ValueError('invalid intent opening binding')
        if value['answer'] is not None:
            _answer(value['answer'])


def _answer(value: Any, *, stored: bool = True) -> None:
    fields = {'text', 'source_kind', 'source_ref', 'principal', 'event_id', 'target_digest'}
    if stored and isinstance(value, dict) and 'resolution' in value:
        fields.add('resolution')
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('invalid closed human answer')
    if (value['source_kind'] != 'human' or not _text(value['text']) or
            not _text(value['source_ref'], 1024) or not _text(value['principal'], 128) or
            value['event_id'] is not None and not _identifier(value['event_id']) or
            not isinstance(value['target_digest'], str) or not _HEX.fullmatch(value['target_digest']) or
            value.get('resolution', 'answered') not in {'answered', 'withdrawn'}):
        raise ValueError('answer requires explicit human source and current target binding')


def validate_intent(value: Any) -> None:
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'revision', 'questions', 'operations'} or
            type(value['schema_version']) is not int or value['schema_version'] != 1 or
            type(value['revision']) is not int or value['revision'] < 0 or
            not isinstance(value['questions'], list) or len(value['questions']) > MAX_QUESTIONS or
            not isinstance(value['operations'], list) or len(value['operations']) > MAX_OPERATIONS):
        raise ValueError('invalid or unsupported task intent')
    ids = set()
    for question in value['questions']:
        _question(question, stored=True)
        if question['id'] in ids:
            raise ValueError('duplicate intent question')
        ids.add(question['id'])
    operations = set()
    for operation in value['operations']:
        fields = {'id', 'digest'}
        if isinstance(operation, dict) and 'answer' in operation:
            fields |= {'question_id', 'answer'}
        if (not isinstance(operation, dict) or set(operation) != fields or
                not _identifier(operation['id']) or operation['id'] in operations or
                not isinstance(operation['digest'], str) or not _HEX.fullmatch(operation['digest'])):
            raise ValueError('invalid intent replay record')
        if 'answer' in operation:
            if operation['question_id'] not in ids:
                raise ValueError('intent history references an unknown question')
            _answer(operation['answer'])
        operations.add(operation['id'])
    if len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode()) > MAX_INTENT_BYTES:
        raise ValueError('intent byte limit reached; existing questions must be preserved')


def _targets(root: Path, route: dict[str, Any]) -> dict[str, Any]:
    from .continuity import package_documents
    from .spec import requirement_targets
    documents = package_documents(root, route, gate=False)
    targets = requirement_targets(documents['spec']) if documents else {}
    # Whole-task questions include all incorporated requirements; typed questions do not.
    targets['original'] = {'task': route['task'], 'requirements': documents['requirements_digest'] if documents else None,
                           'typed': dict(targets), 'pending': route.get('context', {}).get('pending', [])}
    targets.update({item['id']: {'text': item['text'], 'digest': item['digest']}
                    for item in route.get('context', {}).get('pending', [])})
    return targets


def target_digest(root: Path, route: dict[str, Any], question: dict[str, Any], *, allow_missing: bool = False) -> str:
    targets = _targets(root, route)
    if not allow_missing and any(identifier not in targets for identifier in question['targets']):
        raise ValueError('intent references a missing requirement')
    return _digest({'question': question['question'], 'paths': sorted(question['paths']),
                    'targets': {identifier: targets.get(identifier, {'absent': True}) for identifier in sorted(question['targets'])}})


def intent_gaps(root: Path, route: dict[str, Any], *, requirement_ids: tuple[str, ...] | None = None) -> list[str]:
    if 'intent_state' not in route:
        return []
    try:
        validate_intent(route['intent_state'])
        if requirement_ids is not None:
            available = _targets(root, route)
            if not requirement_ids or any(item not in available for item in requirement_ids):
                raise ValueError('intent implementation scope is unavailable')
        gaps = []
        for question in route['intent_state']['questions']:
            if requirement_ids is not None and 'original' not in question['targets'] and not set(requirement_ids) & set(question['targets']):
                continue
            answer = question['answer']
            if answer is None:
                gaps.append(f"intent_unresolved: {question['id']}: {question['question']}")
                continue
            try:
                current = target_digest(root, route, question, allow_missing=answer.get('resolution') == 'withdrawn')
            except (OSError, ValueError, KeyError, TypeError):
                current = None
            if current != answer['target_digest']:
                gaps.append(f"intent_stale: {question['id']}: affected requirements changed; ask the human about the current version")
        return gaps
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return ['intent_invalid: ' + str(exc)]


def _pending_regions(route: dict) -> list[dict]:
    """Only an exact pending ID and explicit affected paths can narrow its impact."""
    context = route.get('context') or {}
    questions = (route.get('intent_state') or {}).get('questions', [])
    regions = []
    for item in context.get('pending', []):
        mapped = [question for question in questions if item['id'] in question['targets']]
        scoped = bool(mapped) and all(question['paths'] and 'original' not in question['targets'] for question in mapped)
        regions.append({'id': item['id'], 'paths': sorted({path for question in mapped for path in question['paths']}) if scoped else [],
                        'targets': sorted({target for question in mapped for target in question['targets'] if not target.startswith('scope-')}) if scoped else []})
    if context.get('rejected'):
        regions.append({'id': context['rejected']['id'], 'paths': [], 'targets': []})
    return regions


def write_scope_gaps(root: Path, route: dict, *, requirement_ids: tuple[str, ...] | None = None) -> list[str]:
    gaps = intent_gaps(root, route, requirement_ids=requirement_ids)
    if requirement_ids is not None:
        try:
            available = _targets(root, route)
            if not requirement_ids or any(item not in available for item in requirement_ids):
                raise ValueError('implementation requirement scope is unavailable')
        except (ValueError, OSError, KeyError, TypeError) as exc:
            return [*gaps, 'scope_sync_required: ' + str(exc)]
    for region in _pending_regions(route):
        if requirement_ids is not None and region['targets'] and not set(requirement_ids) & set(region['targets']):
            continue
        gaps.append('scope_sync_required: ' + region['id'] + ': synchronize the amendment and ask the human about unresolved meaning before affected implementation')
    return gaps


@state.serialized_task
def update_intent(root: Path, request: dict[str, Any]) -> dict[str, Any]:
    from .continuity import _changed, normalize_route
    fields = {'version', 'operation_id', 'route_id', 'logical_task_id', 'authority_epoch',
              'context_revision', 'state_revision', 'operation'}
    if (not isinstance(request, dict) or set(request) != fields or type(request['version']) is not int or request['version'] != 1 or
            not all(_identifier(request[name]) for name in ('operation_id', 'route_id', 'logical_task_id')) or
            any(type(request[name]) is not int or request[name] < 0 for name in ('authority_epoch', 'context_revision', 'state_revision'))):
        raise ValueError('invalid closed intent transition request')
    route = normalize_route(root)
    state.require_route_owner(root, route)
    if any(request[name] != route[name] for name in ('route_id', 'logical_task_id', 'authority_epoch')):
        raise ValueError('intent task or authority epoch mismatch')
    intent = copy.deepcopy(route.get('intent_state', {'schema_version': 1, 'revision': 0, 'questions': [], 'operations': []}))
    validate_intent(intent)
    request_digest = _digest(request)
    for prior in intent['operations']:
        if prior['id'] == request['operation_id']:
            if prior['digest'] != request_digest:
                raise ValueError('intent operation replay collision')
            # Repair projections only from the still-owned canonical record.
            state._publish_route_projections(root, route)
            return route
    if request['state_revision'] != route['state_revision'] or request['context_revision'] != route['context']['revision']:
        raise ValueError('stale intent transition revision')
    operation = request['operation']
    if not isinstance(operation, dict):
        raise ValueError('invalid intent operation')
    if operation.get('kind') == 'ask' and set(operation) == {'kind', 'question'}:
        question = copy.deepcopy(operation['question'])
        _question(question, stored=False)
        if any(item['id'] == question['id'] for item in intent['questions']):
            raise ValueError('intent question already exists; preserve its answer history')
        question.update(opened_digest=target_digest(root, route, question), answer=None)
        intent['questions'].append(question)
    elif operation.get('kind') in {'answer', 'withdraw'} and set(operation) == {'kind', 'id', 'answer'}:
        _answer(operation['answer'], stored=False)
        question = next((item for item in intent['questions'] if item['id'] == operation['id']), None)
        if question is None:
            raise ValueError('unknown intent question')
        if operation['answer']['target_digest'] != target_digest(root, route, question, allow_missing=operation['kind'] == 'withdraw'):
            raise ValueError('human answer target binding is stale')
        question['answer'] = copy.deepcopy(operation['answer'])
        question['answer']['resolution'] = 'withdrawn' if operation['kind'] == 'withdraw' else 'answered'
    else:
        raise ValueError('unsupported intent operation; questions cannot be silently removed')
    intent['revision'] += 1
    record = {'id': request['operation_id'], 'digest': request_digest}
    if operation['kind'] in {'answer', 'withdraw'}:
        record.update(question_id=question['id'], answer=copy.deepcopy(question['answer']))
    intent['operations'].append(record)
    validate_intent(intent)
    updated = _changed(route)
    updated['intent_state'] = intent
    updated['context']['legacy_compatible'] = False
    return state._commit_route(root, updated, expected=route)


def _paths_overlap(path: str, affected: str) -> bool:
    """Compare canonical repository-relative paths in both directions at component boundaries."""
    target_parts, affected_parts = PurePosixPath(path).parts, PurePosixPath(affected).parts
    common = min(len(target_parts), len(affected_parts))
    return target_parts[:common] == affected_parts[:common]


def mutation_block_reason(root: Path, event: dict[str, Any], *, execution_cwd: Path | None = None) -> str | None:
    """Use native structured targets and the existing shell parser, not prompt keywords."""
    route = state.get_active_route(root)
    if not route:
        return None
    from . import _policy_legacy as policy
    from .shell_targets import _shell_mutation_targets
    tool = str(event.get('tool_name', ''))
    inputs = event.get('tool_input') or {}
    inputs = inputs if isinstance(inputs, dict) else {}
    lowered = tool.lower()
    write = tool in {'Edit', 'Write', 'apply_patch', 'MultiEdit'} or any(name in lowered for name in ('write_file', 'edit_file', 'delete_file'))
    if lowered in {'agent', 'spawn_agent'}:
        role = policy._agent_type(inputs)
        if role not in policy.write_roles(root) and role != route.get('write_agent'):
            return None
        required = inputs.get('requirement_ids')
        if required is not None and (not isinstance(required, list) or any(not isinstance(item, str) for item in required)):
            return 'intent_invalid: malformed implementation requirement scope'
        gaps = write_scope_gaps(root, route, requirement_ids=tuple(required) if required else None)
        return '; '.join(gaps) or None
    targets, unknown = [], False
    if tool == 'Bash':
        command = inputs.get('command', '')
        if not isinstance(command, str):
            return 'intent_invalid: command scope is unavailable'
        base = '' if execution_cwd is None or execution_cwd == root else str(execution_cwd)
        targets, write, unresolved, blind = _shell_mutation_targets(root, command, initial_base=base,
            initial_unknown=execution_cwd is None)
        unknown = unresolved or blind
        if policy.fsx.WINDOWS and '\\' in command:
            folded, mutation, unresolved, blind = _shell_mutation_targets(root, command.replace('\\', '/'),
                initial_base=base, initial_unknown=execution_cwd is None)
            targets = list(dict.fromkeys([*targets, *folded]))
            write = write or mutation
            unknown = unknown or unresolved or blind
    elif write:
        targets = policy._extract_paths(inputs)
        if tool == 'apply_patch':
            targets += policy._extract_patch_paths(str(inputs.get('command', inputs.get('patch', ''))))
        unknown = not targets
    if not write:
        return None
    gaps = write_scope_gaps(root, route)
    if not gaps:
        return None
    # Clarification documents and report scratch remain editable through their ordinary guards.
    normalized = [policy.safe_relative_path(root, target) if tool == 'Bash' else
                  policy._structured_relative_path(root, target, execution_cwd=execution_cwd) for target in targets]
    package = state.get_active_change(root) or {}
    clarification = {str(package.get('path', '')) + '/' + name for name in ('requirements.md', 'change-spec.yaml', 'test-plan.md', 'tasks.md')}
    technical = tuple('.getzilla/runtime/' + name + '/' for name in
                      ('scratch', 'audit', 'reviews', 'receipts', 'changes', 'checkpoints', 'logs', 'verification-tools'))
    normalized = [path for path in normalized if path not in clarification and
                  not (isinstance(path, str) and path.startswith(technical))]
    if targets and not normalized and not unknown:
        return None
    if unknown or None in normalized or not normalized or any(gap.startswith('intent_invalid:') for gap in gaps):
        return 'Implementation scope cannot establish independence from ' + '; '.join(gaps)
    active_ids = {gap.split(':', 2)[1].strip() for gap in gaps}
    blocked = []
    for question in (route.get('intent_state') or {}).get('questions', []):
        if question['id'] not in active_ids:
            continue
        paths = question['paths']
        if not paths or any(_paths_overlap(path, affected) for path in normalized for affected in paths):
            blocked.append(question['id'])
    reasons = []
    if blocked:
        reasons.append('intent_unresolved: ask the human about ' + ', '.join(blocked) + ' before the affected implementation')
    for region in _pending_regions(route):
        if not region['paths'] or any(_paths_overlap(path, affected) for path in normalized for affected in region['paths']):
            reasons.append('scope_sync_required: ' + region['id'] + ': typed scope synchronization is required before this product write')
    return '; '.join(reasons) or None
