"""Native intake publication: pending latch, exact CAS/ACK and one commit cut.

Only owned native package requirements are supported here. External source ACL,
human decisions and provider operations require their real adapters (Task5).
"""
from __future__ import annotations

import copy
import hashlib
import re
from pathlib import Path

from . import state
from .requirements_intake import (IntakeError, digest, normalized, project_requirements, validate_intake,
                                 reduce_intake, NativeIntakeContext)
from .intake_readiness import assess_readiness
from .workflow_artifacts import canonical_json, _strict_json, _read_regular, WorkflowArtifactError
from .workflow_storage import cas_package_write, change_directory
from .util import now_utc

ZERO = '0' * 64
MAX_RETAINED_BYTES = 1_000_000
MAX_VERSIONS = 64
MAX_EVENTS = 4096
ACTIVE = 'workflow/projections/intake.json'
BASE = 'workflow/projections/intake/'
PHASES = {'awaiting_quiescence', 'documents', 'scope_ack', 'state_prepared', 'state_published', 'recovery_conflict'}


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _hex(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _cut(value):
    return (isinstance(value, dict) and set(value) == {'generation','D','S','R','A','C','M'} and
            type(value['generation']) is int and 1 <= value['generation'] <= MAX_EVENTS and
            all(_hex(value[key]) for key in ('D','S','R','A','C','M')))


def validate_protocol_metadata(value):
    if (not isinstance(value, dict) or set(value) != {'version','required','generation','committed','pending'} or
            type(value['version']) is not int or value['version'] != 1 or value['required'] is not True or
            type(value['generation']) is not int or not 0 <= value['generation'] <= MAX_EVENTS or
            value['committed'] is not None and (not _cut(value['committed']) or value['committed']['generation'] != value['generation']) or
            value['committed'] is None and value['generation'] != 0):
        raise IntakeError('invalid_intake_metadata')
    pending = value['pending']
    if pending is not None and (
            not isinstance(pending, dict) or set(pending) != {'publication_id','intent_digest','old_cut','target_D','target_M','target_state_ref','phase'} or
            any(not _hex(pending[key]) for key in ('publication_id','intent_digest','target_D')) or
            pending['old_cut'] != value['committed'] or pending['phase'] not in PHASES or
            pending['target_M'] is not None and not _hex(pending['target_M']) or
            pending['target_state_ref'] not in {None, BASE+'publications/'+pending['publication_id']+'/state.json'} or
            (pending['target_M'] is None) != (pending['target_state_ref'] is None)):
        raise IntakeError('invalid_intake_pending')


def native_identity(root, route):
    return {'repository': _hash(str(root.resolve()).encode()), 'logical_task_id':route['logical_task_id'],
            'authority_epoch':route['authority_epoch']}


def native_policy(root):
    # This is a source binding to current native policy, not a replacement policy engine.
    raw = _read_regular(root, '.getzilla/config/policy.json', limit=262144)
    return {'version':'native-local-v1','digest':_hash(raw),'decision_required':False}


def cut_digest(cut):
    return digest(cut,'intake-cut-v1') if cut is not None else None


def _boundary(name):
    """Durable protocol boundary; process death here is recoverable from saved intent."""


def _package(root, route):
    package = change_directory(root, route['change_id'])
    selected = state.get_active_change(root)
    if selected != {'change_id':route['change_id'],'path':package.relative_to(root).as_posix()}:
        raise IntakeError('selected_package_mismatch')
    return package


def _raw(root, package, target, *, missing=False):
    try:
        return _read_regular(root, (package/target).relative_to(root).as_posix(), limit=MAX_RETAINED_BYTES)
    except WorkflowArtifactError as error:
        if missing and isinstance(error.__cause__, FileNotFoundError):
            return None
        raise


def _json(root, package, target, *, missing=False):
    raw = _raw(root, package, target, missing=missing)
    return _strict_json(raw, limit=MAX_RETAINED_BYTES) if raw is not None else None


def _put(root, route, package, target, raw, expected):
    current = _raw(root, package, target, missing=True)
    actual = _hash(current) if current is not None else ZERO
    wanted = _hash(raw)
    if actual == wanted:
        return wanted
    if actual != expected:
        raise IntakeError('recovery_conflict')
    return cas_package_write(root, route['change_id'], target, raw, expected)


def _protocol(route):
    context = route.get('context') or {}
    return context.get('intake') if context.get('version') == 2 else None


def _cursor(root, route, protocol):
    from .continuity import _changed
    updated = _changed(route)
    updated['context'].update(version=2, intake=copy.deepcopy(protocol), legacy_compatible=False)
    return state._commit_route(root, updated, expected=route)


def _owned(root):
    from .continuity import normalize_route
    return state.require_route_owner(root, normalize_route(root))


def _request(value):
    if not isinstance(value, dict) or set(value) != {'snapshot','requirements','event'}:
        raise IntakeError('invalid_publication_request')
    data = validate_intake(value['snapshot'])
    if not isinstance(value['requirements'], str) or not value['requirements'].strip():
        raise IntakeError('invalid_requirements')
    event = value['event']
    if (not isinstance(event, dict) or set(event) != {'id','kind'} or
            not isinstance(event['id'], str) or not re.fullmatch('[A-Za-z0-9_.:/-]{1,128}', event['id']) or
            event['kind'] not in {'record','question_round','withdraw'}):
        raise IntakeError('unsupported_decision_ingress')
    return {'snapshot':data,'requirements':value['requirements'],'event':copy.deepcopy(event)}


def _inputs(root, route, data, requirements):
    if data['identity'] != native_identity(root,route):
        raise IntakeError('intake_task_epoch_mismatch')
    policy = native_policy(root)
    if any(data['policy'][key] != policy[key] for key in ('version','digest')):
        raise IntakeError('stale_policy')
    package = _package(root,route)
    relative = (package/'requirements.md').relative_to(root).as_posix()
    for source in data['sources']:
        if source['uri'] != 'native:'+relative or source['locator']['path'] != relative:
            raise IntakeError('unsupported_source_acl')
        if source['sha256'] != _hash(requirements) or source['locator']['end'] > len(requirements.splitlines()):
            raise IntakeError('stale_source')
    if any(row['operation'] != 'develop' or row['resource'] != 'repository' for row in data['permissions']):
        raise IntakeError('unsupported_permission_contract')


def _budget(root, package, data, intent_raw, prior):
    base = package / BASE
    total, versions, entries = 0, 0, 0
    if base.is_symlink():
        raise IntakeError('unsafe_intake_storage')
    if base.exists():
        for path in base.rglob('*'):
            entries += 1
            if entries > 20000 or path.is_symlink():
                raise IntakeError('unsafe_intake_storage')
            if path.is_file():
                raw = _raw(root,package,path.relative_to(package).as_posix())
                total += len(raw)
                versions += path.parent.name == 'versions'
    active = _raw(root,package,ACTIVE,missing=True)
    total += len(active or b'')
    # Reserve complete target+active copies and ACK/context overhead before pending.
    reserve = len(canonical_json(data)) * 3 + len(intent_raw) + len(canonical_json(prior or {})) * 2 + 32768
    version_path = BASE+'versions/'+project_requirements(data)['draft_digest']+'.json'
    if total + reserve > MAX_RETAINED_BYTES or versions >= MAX_VERSIONS and _raw(root,package,version_path,missing=True) is None:
        raise IntakeError('budget_exhausted')
    if prior and len(prior['events']) >= MAX_EVENTS:
        raise IntakeError('budget_exhausted')


def _make_intent(root, route, request, expected_cut, expected_state):
    from .spec import dump_canonical_spec, canonical_spec_digest
    from .continuity import package_documents
    package = _package(root,route)
    protocol = _protocol(route)
    old_cut = protocol['committed'] if protocol else None
    if cut_digest(old_cut) != expected_cut:
        raise IntakeError('stale_expected_cut')
    old_raw = _raw(root,package,ACTIVE,missing=True)
    if (_hash(old_raw) if old_raw is not None else ZERO) != expected_state:
        raise IntakeError('stale_expected_state')
    old_state = _strict_json(old_raw,limit=MAX_RETAINED_BYTES) if old_raw is not None else None
    if old_cut is not None and old_cut['M'] != expected_state:
        raise IntakeError('stale_expected_state')
    documents = package_documents(root,route)
    data = request['snapshot']
    projection = project_requirements(data)
    spec = copy.deepcopy(data['spec'])
    spec['intake'] = {'version':1,'draft_digest':projection['draft_digest']}
    requirements = request['requirements'].encode()
    _inputs(root,route,data,requirements)
    spec_raw = dump_canonical_spec(spec).encode()
    old_files = {target:_hash(_raw(root,package,target)) for target in ('change-spec.yaml','requirements.md')}
    old_files[ACTIVE] = expected_state
    changed = documents['spec_digest'] != canonical_spec_digest(spec) or documents['requirements_digest'] != _hash(requirements)
    targets = ['OBJ-001'] if spec['objective']['id'] == 'OBJ-001' else [spec['objective']['id']]
    mapping = {'original':targets, **{row['id']:targets for row in route['context']['pending']}}
    ack_template = {'version':1,'route_id':route['route_id'],'logical_task_id':route['logical_task_id'],
                    'authority_epoch':route['authority_epoch'],'revision':route['context']['revision'],
                    'spec_digest':canonical_spec_digest(spec),'requirements_digest':_hash(requirements),'items':mapping} if changed else None
    if route['context']['rejected'] is not None:
        raise IntakeError('rejected_scope_unresolved')
    core = {'identity':native_identity(root,route),'route_id':route['route_id'],'old_cut':old_cut,
            'old_generation':protocol['generation'] if protocol else 0,'expected_state':expected_state,
            'D':projection['draft_digest'],'S':canonical_spec_digest(spec),'R':_hash(requirements),
            'request_digest':digest(request,'intake-request-v1'),'event_digest':digest(request['event'],'intake-event-v1'),
            'ack_template':ack_template,'scope_revision':route['context']['revision']}
    transaction = digest(core,'publication-v1')
    ack = {**ack_template,'operation_id':'intake-ack:'+transaction} if ack_template is not None else None
    return {'version':1,'core':core,'publication_id':transaction,'old_files':old_files,
            'spec':spec_raw.decode(),'requirements':request['requirements'],'event':request['event'],
            'at':now_utc(),'old_state':old_state,'ack_request':ack}


def publication_id(root, intent, expected_cut_digest, expected_state_digest):
    request = _request(intent)
    route = _owned(root)
    package = _package(root,route)
    request_digest = digest(request,'intake-request-v1')
    # Diagnostic/replay lookup only; recover validates full saved identity and payload.
    for path in (package/(BASE+'publications')).glob('*.json'):
        saved = _json(root,package,path.relative_to(package).as_posix())
        if (saved['core']['request_digest'] == request_digest and
                cut_digest(saved['core']['old_cut']) == expected_cut_digest and
                saved['core']['expected_state'] == expected_state_digest):
            return saved['publication_id']
    return _make_intent(root,route,request,expected_cut_digest,expected_state_digest)['publication_id']


def _result(target):
    return {'publication_id':target['publication_id'], 'cut':{'generation':target['generation'],
            **target['bindings'],'M':_hash(canonical_json(target))}}


def _validate_intent(root, route, package, transaction, saved):
    if (not isinstance(saved,dict) or set(saved) != {'version','core','publication_id','old_files','spec','requirements','event','at','old_state','ack_request'} or
            saved['version'] != 1 or saved['publication_id'] != transaction or digest(saved['core'],'publication-v1') != transaction or
            saved['core']['identity'] != native_identity(root,route) or saved['core']['route_id'] != route['route_id']):
        raise IntakeError('invalid_saved_intent')
    data = _json(root,package,BASE+'versions/'+saved['core']['D']+'.json')
    projection = project_requirements(data)
    from .spec import _parse_canonical_json, canonical_spec_digest
    spec = _parse_canonical_json(saved['spec'].encode(),package/'change-spec.yaml')
    request = _request({'snapshot':data,'requirements':saved['requirements'],'event':saved['event']})
    template = saved['core']['ack_template']
    if (projection['draft_digest'] != saved['core']['D'] or canonical_spec_digest(spec) != saved['core']['S'] or
            normalized({k:v for k,v in spec.items() if k != 'intake'}) != data['spec'] or
            spec.get('intake') != {'version':1,'draft_digest':saved['core']['D']} or
            _hash(saved['requirements'].encode()) != saved['core']['R'] or
            digest(request,'intake-request-v1') != saved['core']['request_digest'] or
            digest(saved['event'],'intake-event-v1') != saved['core']['event_digest'] or
            saved['ack_request'] != ({**template,'operation_id':'intake-ack:'+transaction} if template is not None else None)):
        raise IntakeError('invalid_saved_intent')
    _inputs(root,route,data,saved['requirements'].encode())
    return projection


@state.serialized_task
def prepare_intake(root, intent, expected_cut_digest, expected_state_digest):
    """Supported native owner ingress. Staged data and native ACK never approve a draft."""
    try:
        request = _request(intent)
        route = _owned(root)
        package = _package(root,route)
        _inputs(root,route,request['snapshot'],request['requirements'].encode())
        protocol = _protocol(route)
        if protocol and protocol['pending']:
            transaction = protocol['pending']['publication_id']
            saved = _json(root,package,BASE+'publications/'+transaction+'.json')
            if saved['core']['request_digest'] != digest(request,'intake-request-v1'):
                raise IntakeError('another_publication_pending')
            return recover_intake(root,transaction)
        previous = _json(root,package,ACTIVE,missing=True)
        for event in (previous or {}).get('events',[]):
            if event['id'] == request['event']['id']:
                if event['request_digest'] != digest(request,'intake-request-v1'):
                    raise IntakeError('event_collision')
                return recover_intake(root,event['publication_id'])
        saved = _make_intent(root,route,request,expected_cut_digest,expected_state_digest)
        transaction = saved['publication_id']
        input_path = BASE+'versions/'+saved['core']['D']+'.json'
        intent_path = BASE+'publications/'+transaction+'.json'
        # Exact staged replay must retain the original timestamp, payload and old-state bytes.
        existing = _json(root,package,intent_path,missing=True)
        if existing is not None:
            _validate_intent(root,route,package,transaction,existing)
            if existing['core'] != saved['core'] or existing['event'] != saved['event']:
                raise IntakeError('publication_collision')
            saved = existing
        raw = canonical_json(saved)
        _budget(root,package,request['snapshot'],raw,previous)
        _put(root,route,package,input_path,canonical_json(request['snapshot']),ZERO)
        _put(root,route,package,intent_path,raw,ZERO)
        _boundary('staged')
        protocol = copy.deepcopy(protocol) if protocol else {'version':1,'required':True,'generation':0,'committed':None,'pending':None}
        protocol['pending'] = {'publication_id':transaction,'intent_digest':_hash(raw),'old_cut':protocol['committed'],
                               'target_D':saved['core']['D'],'target_M':None,'target_state_ref':None,'phase':'awaiting_quiescence'}
        _cursor(root,route,protocol)
        _boundary('pending')
        return recover_intake(root,transaction)
    except IntakeError:
        raise
    except (ValueError,OSError,KeyError,TypeError) as error:
        raise IntakeError('intake_publication_unavailable') from error


@state.serialized_task
def recover_intake(root, publication_id):
    try:
        if not _hex(publication_id):
            raise IntakeError('invalid_publication_id')
        route = _owned(root)
        package = _package(root,route)
        saved = _json(root,package,BASE+'publications/'+publication_id+'.json')
        projection = _validate_intent(root,route,package,publication_id,saved)
        protocol = copy.deepcopy(_protocol(route))
        pending = protocol and protocol['pending']
        target_path = BASE+'publications/'+publication_id+'/state.json'
        if pending is None:
            target = _json(root,package,target_path)
            result = _result(target)
            current = _json(root,package,ACTIVE)
            if not protocol or not any(row['publication_id'] == publication_id for row in current['events']):
                raise IntakeError('publication_not_committed')
            return result
        if pending['publication_id'] != publication_id or pending['intent_digest'] != _hash(canonical_json(saved)):
            raise IntakeError('pending_intent_mismatch')
        if protocol['committed'] != saved['core']['old_cut'] or protocol['generation'] != saved['core']['old_generation']:
            raise IntakeError('stale_publication_cut')
        from .continuity import _active_workers, ack_scope, context_binding, package_documents, scope_gaps
        from .policy import write_roles
        roles = write_roles(root) | {route.get('write_agent')}
        if any(row['agent_type'] in roles for row in _active_workers(root).values()):
            raise IntakeError('writer_quiescence_required')
        revision = route['context']['revision']
        old_revision = saved['core']['scope_revision']
        ack = route['context']['last_ack']
        if revision != old_revision and not (saved['ack_request'] and revision == old_revision+1 and ack and ack['operation_id'] == saved['ack_request']['operation_id']):
            raise IntakeError('stale_scope_revision')
        for target,raw,boundary in [('change-spec.yaml',saved['spec'].encode(),'spec'), ('requirements.md',saved['requirements'].encode(),'requirements')]:
            _put(root,route,package,target,raw,saved['old_files'][target])
            _boundary(boundary)
        protocol['pending']['phase']='documents'
        route = _cursor(root,route,protocol)
        if saved['ack_request'] is not None:
            route = ack_scope(root,saved['ack_request'])
        if scope_gaps(root,route):
            raise IntakeError('scope_sync_required')
        _boundary('ack')
        binding = context_binding(root,route)
        documents = package_documents(root,route)
        a = digest({'ack':route['context']['last_ack'],'mirror':documents['state'].get('scope_ack')},'native-ack-v1')
        bindings = {'D':saved['core']['D'],'S':binding['spec_digest'],'R':binding['requirements_digest'],'A':a,'C':binding['digest']}
        old = saved['old_state']
        previous = {key:old[key] for key in ('identity','events','rounds','withdrawn')} if old else None
        reduced = reduce_intake(previous,saved['event'],NativeIntakeContext(
            identity=native_identity(root,route), request_digest=saved['core']['request_digest'],
            publication_id=publication_id, at=saved['at']))
        rounds, withdrawn = reduced['rounds'], reduced['withdrawn']
        assessment = assess_readiness(documents['spec'],projection,{**projection['input']['policy'],'rounds':rounds})
        target = {'version':1,'publication_id':publication_id,'generation':protocol['generation']+1,
                  'identity':native_identity(root,route),'bindings':bindings,'projection':projection,
                  'assessment':assessment,'rounds':rounds,'withdrawn':withdrawn,
                  'events':reduced['events']}
        target_raw = canonical_json(target)
        if len(target_raw)>MAX_RETAINED_BYTES:
            raise IntakeError('budget_exhausted')
        _put(root,route,package,target_path,target_raw,ZERO)
        _boundary('target_state')
        protocol['pending'].update(phase='state_prepared',target_M=_hash(target_raw),target_state_ref=target_path)
        route = _cursor(root,route,protocol)
        _put(root,route,package,ACTIVE,target_raw,saved['old_files'][ACTIVE])
        _boundary('state')
        # Native context excludes cursors; live files/source/ACK must still match this target.
        if context_binding(root,route)['digest'] != bindings['C'] or scope_gaps(root,route):
            raise IntakeError('context_changed_during_publication')
        _inputs(root,route,projection['input'],_raw(root,package,'requirements.md'))
        if _hash(_raw(root,package,ACTIVE)) != _hash(target_raw):
            raise IntakeError('state_changed_during_publication')
        result = _result(target)
        protocol.update(generation=target['generation'],committed=result['cut'],pending=None)
        _cursor(root,route,protocol)
        _boundary('commit')
        return result
    except IntakeError:
        raise
    except (ValueError,OSError,KeyError,TypeError) as error:
        raise IntakeError('intake_recovery_unavailable') from error


def read_intake_cut(root):
    try:
        from .continuity import context_binding, package_documents, scope_gaps
        route = state.require_route_owner(root)
        protocol = _protocol(route)
        if protocol is None:
            return {'status':'not_run','reason':'semantic_intake_undeclared'}
        if protocol['pending'] is not None or protocol['committed'] is None:
            raise IntakeError('intake_publication_pending')
        if scope_gaps(root,route):
            raise IntakeError('scope_sync_required')
        package = _package(root,route)
        cut = protocol['committed']
        raw = _raw(root,package,ACTIVE)
        if _hash(raw) != cut['M']:
            raise IntakeError('intake_state_mismatch')
        stored = _strict_json(raw,limit=MAX_RETAINED_BYTES)
        data = _json(root,package,BASE+'versions/'+cut['D']+'.json')
        projection = project_requirements(data)
        if projection['draft_digest'] != cut['D'] or stored['projection'] != projection:
            raise IntakeError('intake_draft_mismatch')
        documents = package_documents(root,route)
        _inputs(root,route,data,documents['requirements'])
        binding = context_binding(root,route)
        a = digest({'ack':route['context']['last_ack'],'mirror':documents['state'].get('scope_ack')},'native-ack-v1')
        observed = {'D':projection['draft_digest'],'S':binding['spec_digest'],'R':binding['requirements_digest'],'A':a,'C':binding['digest']}
        if (stored['identity'] != native_identity(root,route) or stored['generation'] != cut['generation'] or
                stored['bindings'] != observed or any(cut[key] != observed[key] for key in observed) or
                documents['spec'].get('intake') != {'version':1,'draft_digest':cut['D']}):
            raise IntakeError('intake_binding_mismatch')
        policy = native_policy(root)
        policy['decision_required'] = data['policy']['decision_required']
        assessment = assess_readiness(documents['spec'],projection,{**policy,'rounds':stored['rounds']})
        if stored['withdrawn']:
            raise IntakeError('intake_withdrawn')
        if (state.canonical_route(root,route['route_id']) != route or
                _raw(root,package,ACTIVE) != raw or package_documents(root,route) != documents or
                context_binding(root,route) != binding):
            raise IntakeError('intake_changed_during_read')
        return {'status':'observed','cut':copy.deepcopy(cut),'assessment':assessment}
    except IntakeError:
        raise
    except (ValueError,OSError,KeyError,TypeError) as error:
        raise IntakeError('intake_read_unavailable') from error


def require_intake_ready(root, route=None, operation_class='product-write'):
    current = state.get_active_route(root)
    if route is not None and route != current:
        raise IntakeError('intake_route_changed')
    if current is None:
        if state.route_authority_present(root):
            raise IntakeError('intake_authority_unavailable')
        return {'status':'not_run','reason':'semantic_intake_undeclared'}
    result = read_intake_cut(root)
    if result['status'] != 'not_run' and result['assessment']['status'] != 'ready':
        raise IntakeError('intake_not_ready')
    return result
