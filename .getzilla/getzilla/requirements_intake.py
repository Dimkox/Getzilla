"""Bounded advisory provenance for the existing native task/spec projection.

No field in this wire contract originates authority, approval or provider effects.
"""
from __future__ import annotations

import copy
import hashlib
import itertools
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from .spec import _validate_document, load_schema, validate_schema
from .workflow_storage import canonical_json, _strict_json, MAX_SOURCE_BYTES


class IntakeError(ValueError):
    """A safe fixed reason; never includes untrusted source values."""


@dataclass(frozen=True)
class NativeIntakeContext:
    """Native producer bindings, not a deserializable approval or principal."""
    identity: dict
    request_digest: str
    publication_id: str
    at: str


def reduce_intake(previous: dict | None, event: dict, trusted: NativeIntakeContext) -> dict:
    if (type(trusted) is not NativeIntakeContext or not isinstance(event, dict) or
            set(event) != {'id', 'kind'} or event['kind'] not in {'record','question_round','withdraw'}):
        raise IntakeError('unsupported_decision_ingress')
    value = copy.deepcopy(previous) if previous else {'identity':trusted.identity,'events':[],'rounds':0,'withdrawn':False}
    if value['identity'] != trusted.identity:
        raise IntakeError('intake_task_epoch_mismatch')
    event_digest = digest(event,'intake-event-v1')
    for row in value['events']:
        if row['id'] == event['id']:
            if row['event_digest'] != event_digest or row['request_digest'] != trusted.request_digest:
                raise IntakeError('event_collision')
            return value
    if len(value['events']) >= 4096:
        raise IntakeError('budget_exhausted')
    value['events'].append({'id':event['id'],'event_digest':event_digest,'request_digest':trusted.request_digest,
                            'publication_id':trusted.publication_id,'at':trusted.at})
    value['rounds'] = min(3,value['rounds'] + (event['kind']=='question_round'))
    value['withdrawn'] = value['withdrawn'] or event['kind']=='withdraw'
    return value


def digest(value: Any, domain: str = 'intake-v1') -> str:
    return hashlib.sha256(domain.encode() + b'\0' + canonical_json(value)).hexdigest()


def normalized(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: normalized(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return sorted((normalized(item) for item in value), key=canonical_json)
    return value


def safe_path(value: str) -> bool:
    parts = PurePosixPath(value).parts
    return bool(parts and not value.startswith('/') and '\\' not in value and
                all(part not in {'.', '..'} for part in parts) and str(PurePosixPath(value)) == value)


def validate_intake(value: object) -> dict:
    from . import STACK_DIR
    try:
        # Reuse the native byte, depth, node, string and nonfinite bounds.
        value = _strict_json(canonical_json(value), limit=MAX_SOURCE_BYTES)
        validate_schema(value, load_schema(STACK_DIR.parent / 'schemas/requirement-intake-v1.schema.json'))
        if 'intake' in value['spec']:
            raise IntakeError('substantive_backreference')
        _validate_document(value['spec'], gate=False)
        sources = value['sources']
        for source in sources:
            # Source tracker status is not substantive input and never an approval.
            source.pop('imported_status', None)
        if len({source['id'] for source in sources}) != len(sources):
            raise IntakeError('duplicate_source')
        if any(source['locator']['start'] > source['locator']['end'] or
               not safe_path(source['locator']['path']) for source in sources):
            raise IntakeError('invalid_locator')
        if any(not safe_path(path) or '*' in path for path in value['scope']):
            raise IntakeError('unbounded_scope')
        requirements = value['requirements']
        if len({row['id'] for row in requirements}) != len(requirements):
            raise IntakeError('duplicate_requirement')
        source_ids = {source['id'] for source in sources}
        criteria = {row['id'] for row in value['spec']['acceptance_criteria']}
        for row in requirements:
            if row['source_id'] not in source_ids or not set(row['criterion_ids']) <= criteria:
                raise IntakeError('unresolved_reference')
            for fact in row['facts']:
                if type(fact['value']) not in {int, str}:
                    raise IntakeError('invalid_fact_value')
                if fact['operator'] in {'at_least', 'at_most'} and type(fact['value']) is not int:
                    raise IntakeError('invalid_bound')
        for group in ('dependencies', 'permissions'):
            keys = [row['id'] if group == 'dependencies' else (row['operation'], row['resource']) for row in value[group]]
            if len(set(keys)) != len(keys):
                raise IntakeError('duplicate_requirement')
        return normalized(value)
    except IntakeError:
        raise
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError) as error:
        raise IntakeError('invalid_intake') from error


def _contradicts(left: dict, right: dict) -> bool:
    a, b = left['value'], right['value']
    x, y = left['operator'], right['operator']
    if {x, y} == {'requires', 'forbids'}:
        return a == b
    if x == y == 'equals':
        return a != b
    if x == 'equals' and y in {'at_least', 'at_most'} and type(a) is int:
        return a < b if y == 'at_least' else a > b
    if y == 'equals':
        return _contradicts(right, left) if x != 'equals' else False
    return (x == 'at_least' and y == 'at_most' and a > b or
            y == 'at_least' and x == 'at_most' and b > a)


def _comparable(left: dict, right: dict) -> bool:
    operators = {left['operator'],right['operator']}
    if operators & {'at_least','at_most'}:
        return (operators <= {'equals','at_least','at_most'} and
                type(left['value']) is int and type(right['value']) is int)
    return (type(left['value']) is type(right['value']) and
            (operators <= {'requires','forbids'} or operators == {'equals'}))


def project_requirements(snapshot: dict, prior: dict | None = None) -> dict:
    data = validate_intake(snapshot)
    draft = digest(data, 'substantive-draft-v1')
    conflicts, unknown = [], set()
    source_versions = {}
    for source in data['sources']:
        key = (source['uri'],canonical_json(source['locator']))
        source_versions.setdefault(key,set()).add((source['version'],source['sha256']))
    if any(len(versions)>1 for versions in source_versions.values()):
        unknown.add('ambiguous_source_version')
    facts = [(row, fact) for row in data['requirements'] for fact in row['facts']]
    if any(fact['unit'] not in {None, 'count', 'days', 'hours', 'bytes'} for _, fact in facts):
        unknown.add('unsupported_unit')
    for (left, a), (right, b) in itertools.combinations(facts, 2):
        if tuple(a[key] for key in ('subject', 'scope', 'facet')) != tuple(b[key] for key in ('subject', 'scope', 'facet')):
            continue
        if a['unit'] != b['unit']:
            unknown.add('incomparable_units')
            continue
        if a['unit'] not in {None, 'count', 'days', 'hours', 'bytes'}:
            unknown.add('unsupported_unit')
            continue
        if not _comparable(a,b):
            unknown.add('incomparable_values')
            continue
        if _contradicts(a, b):
            refs = sorted({left['id'], right['id']})
            sources = sorted({left['source_id'], right['source_id']})
            conflicts.append({'reason': 'contradictory_fact', 'requirements': refs, 'sources': sources})
    if any(not row['facts'] or row['interpretations'] for row in data['requirements']):
        unknown.add('semantic_conflict_unassessed')
    actions = {}
    # Prior correspondence is retained data only. No imported field can cause an effect.
    previous = {row['id']: row for row in (prior or {}).get('actions', [])}
    for row in data['requirements']:
        if row['action_key'] is None:
            unknown.add('unresolved_mapping')
            continue
        identity = digest([data['identity']['repository'], data['identity']['logical_task_id'], row['source_id'], row['action_key']], 'source-action-v1')
        old = previous.get(identity)
        actions[identity] = {'id': identity, 'source_id': row['source_id'], 'action_key': row['action_key'],
                             'external': copy.deepcopy(old['external']) if old else {'status': 'planned', 'resource': None},
                             'create_eligible': False}
    # Source edits/removal do not prove an earlier external operation had no
    # effect. Keep unmatched UNKNOWN correspondence in this same projection
    # until its actual operation owner can reconcile it.
    for identity, old in previous.items():
        if identity not in actions and old['external'].get('status') == 'unknown':
            actions[identity] = {'id':identity,'source_id':old['source_id'],'action_key':old['action_key'],
                                 'external':copy.deepcopy(old['external']),'create_eligible':False}
            unknown.add('unresolved_mapping')
    stale = ['stale_draft'] if prior and prior.get('draft_digest') != draft and prior.get('decisions') else []
    conflicts = sorted({canonical_json(row): row for row in conflicts}.values(), key=canonical_json)
    result = {'version': 1, 'draft_digest': draft, 'input': data,
              'status': 'completed_empty' if not data['requirements'] else 'conflicted' if conflicts else 'draft',
              'conflicts': conflicts, 'unknown': sorted(unknown), 'stale': stale,
              'actions': [actions[key] for key in sorted(actions)], 'decisions': copy.deepcopy((prior or {}).get('decisions', [])),
              'authority': False, 'receipt_eligible': False}
    result['projection_digest'] = digest(result, 'requirement-projection-v1')
    return result
