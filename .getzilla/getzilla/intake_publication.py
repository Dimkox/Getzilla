"""Native intake publication: pending latch, exact CAS/ACK and one commit cut.

Only owned native package requirements are supported here. External source ACL,
human decisions and provider operations require their real adapters (Task5).
"""
from __future__ import annotations

import copy
import hashlib
import re

from . import state
from .requirements_intake import (IntakeError, digest, normalized as normalized, project_requirements, validate_intake,
                                 reduce_intake as reduce_intake, NativeIntakeContext as NativeIntakeContext,
                                 earlier_task_epoch as earlier_task_epoch)
from .intake_readiness import assess_readiness, question_limits
from .workflow_artifacts import canonical_json, _strict_json, _read_regular, WorkflowArtifactError
from .workflow_storage import cas_package_write as cas_package_write, change_directory
from .util import now_utc as now_utc

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
    if (not isinstance(value, dict) or set(value) not in ({'version','required','generation','committed','pending'},
            {'version','required','generation','committed','pending','native_decision'}) or
            type(value['version']) is not int or value['version'] != 1 or value['required'] is not True or
            type(value['generation']) is not int or not 0 <= value['generation'] <= MAX_EVENTS or
            value['committed'] is not None and (not _cut(value['committed']) or value['committed']['generation'] != value['generation']) or
            value['committed'] is None and value['generation'] != 0):
        raise IntakeError('invalid_intake_metadata')
    if 'native_decision' in value:
        from .intake_decisions import validate_stamp
        validate_stamp(value['native_decision'])
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
    decoded = _strict_json(raw,limit=262144)
    if type(decoded) is not dict:
        raise IntakeError('invalid_intake_policy')
    configured = decoded.get('intake')
    values = ({key:configured.get(key) for key in ('max_questions_per_round','max_question_rounds')}
              if type(configured) is dict else None)
    decision = configured.get('decision_required',False) if type(configured) is dict else False
    if type(decision) is not bool:
        raise IntakeError('invalid_intake_policy')
    return {'version':'native-local-v1','digest':_hash(raw),'decision_required':decision,
            'question_limits':copy.deepcopy(values) if question_limits({'question_limits':values}) else None}


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
    from . import intake_authoring as authoring
    return authoring._put(root, route, package, target, raw, expected)


def _protocol(route):
    context = route.get('context') or {}
    return context.get('intake') if context.get('version') == 2 else None


def _cursor(root, route, protocol):
    from . import intake_authoring as authoring
    return authoring._cursor(root, route, protocol)


def _owned(root):
    from . import intake_authoring as authoring
    return authoring._owned(root)


def _request(value, *, native_stamp=None):
    if not isinstance(value, dict) or set(value) != {'snapshot','requirements','event'}:
        raise IntakeError('invalid_publication_request')
    data = validate_intake(value['snapshot'])
    if not isinstance(value['requirements'], str) or not value['requirements'].strip():
        raise IntakeError('invalid_requirements')
    event = value['event']
    from .intake_decisions import valid_event
    native = (native_stamp is not None and valid_event(event) and event == native_stamp['event'])
    if not native and (not isinstance(event, dict) or set(event) != {'id','kind'} or
            not isinstance(event['id'], str) or not re.fullmatch('[A-Za-z0-9_.:/-]{1,128}', event['id']) or
            event['kind'] not in {'record','question_round','withdraw'}):
        raise IntakeError('unsupported_decision_ingress')
    return {'snapshot':data,'requirements':value['requirements'],'event':copy.deepcopy(event)}


def _inputs(root, route, data, requirements):
    if data['identity'] != native_identity(root,route):
        raise IntakeError('intake_task_epoch_mismatch')
    policy = native_policy(root)
    if any(data['policy'][key] != policy[key] for key in ('version','digest')) or data['policy'].get('question_limits') != policy['question_limits']:
        raise IntakeError('stale_policy')
    if policy['decision_required'] and not data['policy']['decision_required']:
        raise IntakeError('required_decision_cannot_be_disabled')
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
    from . import intake_authoring as authoring
    return authoring._budget(root, package, data, intent_raw, prior)


def _make_intent(root, route, request, expected_cut, expected_state):
    from . import intake_authoring as authoring
    return authoring._make_intent(root, route, request, expected_cut, expected_state)


def publication_id(root, intent, expected_cut_digest, expected_state_digest):
    from . import intake_authoring as authoring
    return authoring.publication_id(root, intent, expected_cut_digest, expected_state_digest)


def _result(target):
    return {'publication_id':target['publication_id'], 'cut':{'generation':target['generation'],
            **target['bindings'],'M':_hash(canonical_json(target))}}


def _epoch_rebind(route, previous):
    from . import intake_authoring as authoring
    return authoring._epoch_rebind(route, previous)


def _validate_intent(root, route, package, transaction, saved):
    from . import intake_authoring as authoring
    return authoring._validate_intent(root, route, package, transaction, saved)


@state.serialized_task
def _prepare_intake(root, intent, expected_cut_digest, expected_state_digest, *, native=False):
    """Supported native owner ingress. Staged data and native ACK never approve a draft."""
    from . import intake_authoring as authoring
    return authoring._prepare_intake(root, intent, expected_cut_digest, expected_state_digest, native=native)


@state.serialized_task
def recover_intake(root, publication_id):
    from . import intake_authoring as authoring
    return authoring.recover_intake(root, publication_id)


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
        from .intake_decisions import current_choice, apply_choice
        choice = current_choice(route,projection,stored['events'],binding['digest'])
        if choice is not None and choice['R'] != observed['R']:
            choice = None
        assessment = apply_choice(assessment,choice)
        if stored['withdrawn']:
            raise IntakeError('intake_withdrawn')
        if (state.canonical_route(root,route['route_id']) != route or
                _raw(root,package,ACTIVE) != raw or package_documents(root,route) != documents or
                context_binding(root,route) != binding):
            raise IntakeError('intake_changed_during_read')
        return {'status':'observed','cut':copy.deepcopy(cut),'cut_digest':cut_digest(cut),'assessment':assessment,
                'native_decision':({**copy.deepcopy(choice),'human_attestation':False} if choice is not None else None)}
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


def trace_requirement(root, criterion_id, delivery=None):
    """Owned local trace; imported PR observations never establish acceptance."""
    observation = read_intake_cut(root)
    if observation['status'] == 'not_run':
        raise IntakeError('intake_trace_unavailable')
    route = state.require_route_owner(root)
    package = _package(root,route)
    stored = _json(root,package,ACTIVE)
    data = stored['projection']['input']
    requirements = [row for row in data['requirements'] if criterion_id in row['criterion_ids']]
    if not requirements:
        raise IntakeError('criterion_unmapped')
    refs = {row['source_id'] for row in requirements}
    tasks, graph_status = [],'not_run'
    graph = _json(root,package,'workflow/task-graph.json',missing=True)
    if graph is not None:
        from .workflow_artifacts import validate_task_graph,load_source_manifest,compile_task_graph
        validate_task_graph(graph)
        bundle = load_source_manifest(root,package/'workflow/manifest.json')
        if graph != compile_task_graph(root,route['change_id'],bundle,route):
            raise IntakeError('stale_task_graph')
        tasks = [row['task_id'] for row in graph['tasks'] if criterion_id in row['covers']]
        graph_status = 'observed'
    delivery_status = 'not_run'
    if delivery is not None:
        if (not isinstance(delivery,dict) or set(delivery) != {'number','state','head_sha','observed_head_sha'} or
                type(delivery['number']) is not int or delivery['number']<1 or
                delivery['state'] not in {'open','closed','merged'} or
                any(not isinstance(delivery[key],str) or re.fullmatch('[0-9a-f]{40}',delivery[key]) is None for key in ('head_sha','observed_head_sha'))):
            raise IntakeError('invalid_delivery_observation')
        delivery_status = 'observed_unqualified' if delivery['head_sha']==delivery['observed_head_sha'] else 'stale'
    # Current ACL/provider/receipt qualification is deliberately not inferred here.
    if read_intake_cut(root) != observation:
        raise IntakeError('intake_changed_during_trace')
    return {'criterion_id':criterion_id,'draft_digest':observation['cut']['D'],'spec_digest':observation['cut']['S'],
            'requirement_ids':sorted(row['id'] for row in requirements),
            'source_refs':[copy.deepcopy(row) for row in data['sources'] if row['id'] in refs],
            'task_ids':sorted(tasks),'task_graph_status':graph_status,'delivery_status':delivery_status,
            'receipt_status':'not_run','accepted':False,'authority':False,'receipt_eligible':False}


def prepare_intake(root, intent, expected_cut_digest, expected_state_digest):
    """Imported records cannot select the explicit native decision ingress."""
    return _prepare_intake(root,intent,expected_cut_digest,expected_state_digest)


@state.serialized_task
def decide_intake(root, *, decision, event_id, expected_cut_digest, expected_state_digest, expected_draft_digest, expected_source_digest):
    """Explicit current native owner action, never an imported yes/human attestation.

    A caller must have actual owner delegation for this substantive choice. No
    prompt, document, scope ACK or saved principal field invokes this operation.
    """
    from . import intake_authoring as authoring
    return authoring.decide_intake(root, decision=decision, event_id=event_id, expected_cut_digest=expected_cut_digest, expected_state_digest=expected_state_digest, expected_draft_digest=expected_draft_digest, expected_source_digest=expected_source_digest)
