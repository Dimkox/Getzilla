"""Native intake authoring leaf; imported only by explicit writer entry points.

The public owner retains canonical helpers, state locks and fault boundaries.
This module does not supply another authority or change publication semantics.
"""
from __future__ import annotations

from . import intake_publication as publication


def _put(root, route, package, target, raw, expected):
    current = publication._raw(root, package, target, missing=True)
    actual = publication._hash(current) if current is not None else publication.ZERO
    wanted = publication._hash(raw)
    if actual == wanted:
        return wanted
    if actual != expected:
        raise publication.IntakeError('recovery_conflict')
    return publication.cas_package_write(root, route['change_id'], target, raw, expected)


def _cursor(root, route, protocol):
    from .continuity import _changed
    updated = _changed(route)
    updated['context'].update(version=2, intake=publication.copy.deepcopy(protocol), legacy_compatible=False)
    return publication.state._commit_route(root, updated, expected=route)


def _owned(root):
    from .continuity import normalize_route
    try:
        return publication.state.require_route_owner(root, normalize_route(root))
    except ValueError as error:
        raise publication.IntakeError('intake_owner_required') from error


def _budget(root, package, data, intent_raw, prior):
    base = package / publication.BASE
    total, versions, entries = 0, 0, 0
    if base.is_symlink():
        raise publication.IntakeError('unsafe_intake_storage')
    if base.exists():
        for path in base.rglob('*'):
            entries += 1
            if entries > 20000 or path.is_symlink():
                raise publication.IntakeError('unsafe_intake_storage')
            if path.is_file():
                raw = publication._raw(root,package,path.relative_to(package).as_posix())
                total += len(raw)
                versions += path.parent.name == 'versions'
                if total > publication.MAX_RETAINED_BYTES:
                    raise publication.IntakeError('budget_exhausted')
    recovery = root/'.getzilla/runtime/workflow-cas'/package.name
    if recovery.is_symlink():
        raise publication.IntakeError('unsafe_intake_storage')
    if recovery.exists():
        for path in recovery.iterdir():
            entries += 1
            if entries > 20000 or path.is_symlink() or not path.is_file():
                raise publication.IntakeError('unsafe_intake_storage')
            total += len(publication._read_regular(root,path.relative_to(root).as_posix(),limit=publication.MAX_RETAINED_BYTES))
            if total > publication.MAX_RETAINED_BYTES:
                raise publication.IntakeError('budget_exhausted')
    active = publication._raw(root,package,publication.ACTIVE,missing=True)
    total += len(active or b'')
    # Reserve complete target+active copies and ACK/context overhead before pending.
    # Count CAS recovery copies too. Reserve an upper bound for both live and
    # retained input/intent/target/document copies before any pending latch.
    previous_bytes = len(publication.canonical_json(prior or {}))
    input_bytes = len(publication.canonical_json(data))
    saved = publication._strict_json(intent_raw,limit=publication.MAX_RETAINED_BYTES)
    target_bound = input_bytes*2 + previous_bytes*2 + 16384
    reserve = (input_bytes*2 + len(intent_raw)*2 + target_bound*3 + previous_bytes +
               len(saved['spec'].encode())*2 + len(saved['requirements'].encode())*2)
    version_path = publication.BASE+'versions/'+publication.project_requirements(data)['draft_digest']+'.json'
    if total + reserve > publication.MAX_RETAINED_BYTES or versions >= publication.MAX_VERSIONS and publication._raw(root,package,version_path,missing=True) is None:
        raise publication.IntakeError('budget_exhausted')
    if prior and len(prior['events']) >= publication.MAX_EVENTS:
        raise publication.IntakeError('budget_exhausted')


def _make_intent(root, route, request, expected_cut, expected_state):
    from .spec import dump_canonical_spec, canonical_spec_digest
    from .continuity import package_documents
    package = publication._package(root,route)
    protocol = publication._protocol(route)
    old_cut = protocol['committed'] if protocol else None
    if publication.cut_digest(old_cut) != expected_cut:
        raise publication.IntakeError('stale_expected_cut')
    old_raw = publication._raw(root,package,publication.ACTIVE,missing=True)
    if (publication._hash(old_raw) if old_raw is not None else publication.ZERO) != expected_state:
        raise publication.IntakeError('stale_expected_state')
    old_state = publication._strict_json(old_raw,limit=publication.MAX_RETAINED_BYTES) if old_raw is not None else None
    if request['event']['kind'] == 'question_round':
        limits = publication.question_limits(publication.native_policy(root))
        if limits is None:
            raise publication.IntakeError('question_limits_unconfigured')
        if (old_state or {}).get('rounds',0) >= limits['max_question_rounds']:
            raise publication.IntakeError('question_budget_exhausted')
    if old_cut is not None and old_cut['M'] != expected_state:
        raise publication.IntakeError('stale_expected_state')
    documents = package_documents(root,route,draft=True)
    data = request['snapshot']
    projection = publication.project_requirements(data)
    spec = publication.copy.deepcopy(data['spec'])
    spec['intake'] = {'version':1,'draft_digest':projection['draft_digest']}
    requirements = request['requirements'].encode()
    publication._inputs(root,route,data,requirements)
    spec_raw = dump_canonical_spec(spec).encode()
    old_files = {target:publication._hash(publication._raw(root,package,target)) for target in ('change-spec.yaml','requirements.md')}
    old_files[publication.ACTIVE] = expected_state
    changed = documents['spec_digest'] != canonical_spec_digest(spec) or documents['requirements_digest'] != publication._hash(requirements)
    targets = ['OBJ-001'] if spec['objective']['id'] == 'OBJ-001' else [spec['objective']['id']]
    mapping = {'original':targets, **{row['id']:targets for row in route['context']['pending']}}
    ack_template = {'version':1,'route_id':route['route_id'],'logical_task_id':route['logical_task_id'],
                    'authority_epoch':route['authority_epoch'],'revision':route['context']['revision'],
                    'spec_digest':canonical_spec_digest(spec),'requirements_digest':publication._hash(requirements),'items':mapping} if changed else None
    if route['context']['rejected'] is not None:
        raise publication.IntakeError('rejected_scope_unresolved')
    core = {'identity':publication.native_identity(root,route),'route_id':route['route_id'],'old_cut':old_cut,
            'old_generation':protocol['generation'] if protocol else 0,'expected_state':expected_state,
            'D':projection['draft_digest'],'S':canonical_spec_digest(spec),'R':publication._hash(requirements),
            'request_digest':publication.digest(request,'intake-request-v1'),'event_digest':publication.digest(request['event'],'intake-event-v1'),
            'ack_template':ack_template,'scope_revision':route['context']['revision']}
    if request['event']['kind'] == 'native_decision':
        stamp = protocol.get('native_decision')
        if stamp is None or stamp['event'] != request['event']:
            raise publication.IntakeError('native_decision_not_admitted')
        core['native_decision_digest'] = publication.digest(stamp,'native-intake-decision-v1')
    transaction = publication.digest(core,'publication-v1')
    ack = {**ack_template,'operation_id':'intake-ack:'+transaction} if ack_template is not None else None
    return {'version':1,'core':core,'publication_id':transaction,'old_files':old_files,
            'spec':spec_raw.decode(),'requirements':request['requirements'],'event':request['event'],
            'at':publication.now_utc(),'old_state':old_state,'ack_request':ack}


def publication_id(root, intent, expected_cut_digest, expected_state_digest):
    request = publication._request(intent)
    route = publication._owned(root)
    package = publication._package(root,route)
    request_digest = publication.digest(request,'intake-request-v1')
    # Diagnostic/replay lookup only; recover validates full saved identity and payload.
    for path in (package/(publication.BASE+'publications')).glob('*.json'):
        saved = publication._json(root,package,path.relative_to(package).as_posix())
        if (saved['core']['request_digest'] == request_digest and
                publication.cut_digest(saved['core']['old_cut']) == expected_cut_digest and
                saved['core']['expected_state'] == expected_state_digest):
            return saved['publication_id']
    return publication._make_intent(root,route,request,expected_cut_digest,expected_state_digest)['publication_id']


def _epoch_rebind(route, previous):
    current = {'repository':previous.get('repository'),
        'logical_task_id':route['logical_task_id'],'authority_epoch':route['authority_epoch']}
    handoff = route.get('handoff') or {}
    return (publication.earlier_task_epoch(previous,current) and handoff.get('to_session') == route['session_id']
            and handoff.get('from_epoch') == route['authority_epoch']-1)


def _validate_intent(root, route, package, transaction, saved):
    if (not isinstance(saved,dict) or set(saved) != {'version','core','publication_id','old_files','spec','requirements','event','at','old_state','ack_request'} or
            saved['version'] != 1 or saved['publication_id'] != transaction or publication.digest(saved['core'],'publication-v1') != transaction or
            saved['core']['identity'] != publication.native_identity(root,route) or saved['core']['route_id'] != route['route_id']):
        raise publication.IntakeError('invalid_saved_intent')
    # Before pending, the retained intent is untrusted data. Its prior payload
    # must rederive the real previous M, including withdrawal/history/counters.
    # Hashing the requested core alone does not bind these reducer inputs.
    core, old = saved['core'], saved['old_state']
    expected = core['expected_state']
    if old is None:
        if expected != publication.ZERO or core['old_cut'] is not None or core['old_generation'] != 0:
            raise publication.IntakeError('invalid_previous_state')
    elif (not isinstance(old,dict) or not publication._hex(expected) or publication._hash(publication.canonical_json(old)) != expected or
          not publication._cut(core['old_cut']) or core['old_cut']['M'] != expected or
          core['old_cut']['generation'] != core['old_generation'] or
          (old.get('identity') != core['identity'] and not (publication.earlier_task_epoch(old.get('identity'),core['identity']) and publication._epoch_rebind(route,old['identity']))) or publication._result(old)['cut'] != core['old_cut']):
        raise publication.IntakeError('invalid_previous_state')
    if saved['old_files'].get(publication.ACTIVE) != expected:
        raise publication.IntakeError('invalid_previous_state')
    data = publication._json(root,package,publication.BASE+'versions/'+saved['core']['D']+'.json')
    projection = publication.project_requirements(data)
    from .spec import _parse_canonical_json, canonical_spec_digest
    spec = _parse_canonical_json(saved['spec'].encode(),package/'change-spec.yaml')
    stamp = (publication._protocol(route) or {}).get('native_decision')
    request = publication._request({'snapshot':data,'requirements':saved['requirements'],'event':saved['event']},native_stamp=stamp)
    if saved['event']['kind'] == 'native_decision':
        if (stamp is None or stamp['principal'] != route['session_id']
                or stamp['identity'] != publication.native_identity(root,route)
                or saved['core'].get('native_decision_digest') != publication.digest(stamp,'native-intake-decision-v1')):
            raise publication.IntakeError('native_decision_not_admitted')
    template = saved['core']['ack_template']
    if (projection['draft_digest'] != saved['core']['D'] or canonical_spec_digest(spec) != saved['core']['S'] or
            publication.normalized({k:v for k,v in spec.items() if k != 'intake'}) != data['spec'] or
            spec.get('intake') != {'version':1,'draft_digest':saved['core']['D']} or
            publication._hash(saved['requirements'].encode()) != saved['core']['R'] or
            publication.digest(request,'intake-request-v1') != saved['core']['request_digest'] or
            publication.digest(saved['event'],'intake-event-v1') != saved['core']['event_digest'] or
            saved['ack_request'] != ({**template,'operation_id':'intake-ack:'+transaction} if template is not None else None)):
        raise publication.IntakeError('invalid_saved_intent')
    publication._inputs(root,route,data,saved['requirements'].encode())
    return projection


def _prepare_intake(root, intent, expected_cut_digest, expected_state_digest, *, native=False):
    """Supported native owner ingress. Staged data and native ACK never approve a draft."""
    try:
        route = publication._owned(root)
        stamp = (publication._protocol(route) or {}).get('native_decision') if native else None
        request = publication._request(intent,native_stamp=stamp)
        package = publication._package(root,route)
        publication._inputs(root,route,request['snapshot'],request['requirements'].encode())
        protocol = publication._protocol(route)
        if protocol and protocol['pending']:
            transaction = protocol['pending']['publication_id']
            saved = publication._json(root,package,publication.BASE+'publications/'+transaction+'.json')
            if saved['core']['request_digest'] != publication.digest(request,'intake-request-v1'):
                raise publication.IntakeError('another_publication_pending')
            return publication.recover_intake(root,transaction)
        previous = publication._json(root,package,publication.ACTIVE,missing=True)
        for event in (previous or {}).get('events',[]):
            if event['id'] == request['event']['id']:
                if event['request_digest'] != publication.digest(request,'intake-request-v1'):
                    raise publication.IntakeError('event_collision')
                return publication.recover_intake(root,event['publication_id'])
        saved = publication._make_intent(root,route,request,expected_cut_digest,expected_state_digest)
        transaction = saved['publication_id']
        input_path = publication.BASE+'versions/'+saved['core']['D']+'.json'
        intent_path = publication.BASE+'publications/'+transaction+'.json'
        # Exact staged replay must retain the original timestamp, payload and old-state bytes.
        existing = publication._json(root,package,intent_path,missing=True)
        if existing is not None:
            publication._validate_intent(root,route,package,transaction,existing)
            if (existing['core'] != saved['core'] or existing['event'] != saved['event'] or
                    existing['old_files'] != saved['old_files']):
                raise publication.IntakeError('publication_collision')
            saved = existing
        raw = publication.canonical_json(saved)
        publication._budget(root,package,request['snapshot'],raw,previous)
        publication._put(root,route,package,input_path,publication.canonical_json(request['snapshot']),publication.ZERO)
        publication._put(root,route,package,intent_path,raw,publication.ZERO)
        publication._boundary('staged')
        protocol = publication.copy.deepcopy(protocol) if protocol else {'version':1,'required':True,'generation':0,'committed':None,'pending':None}
        protocol['pending'] = {'publication_id':transaction,'intent_digest':publication._hash(raw),'old_cut':protocol['committed'],
                               'target_D':saved['core']['D'],'target_M':None,'target_state_ref':None,'phase':'awaiting_quiescence'}
        publication._cursor(root,route,protocol)
        publication._boundary('pending')
        return publication.recover_intake(root,transaction)
    except publication.IntakeError:
        raise
    except (ValueError,OSError,KeyError,TypeError) as error:
        raise publication.IntakeError('intake_publication_unavailable') from error


def recover_intake(root, publication_id):
    try:
        if not publication._hex(publication_id):
            raise publication.IntakeError('invalid_publication_id')
        route = publication._owned(root)
        package = publication._package(root,route)
        saved = publication._json(root,package,publication.BASE+'publications/'+publication_id+'.json')
        projection = publication._validate_intent(root,route,package,publication_id,saved)
        protocol = publication.copy.deepcopy(publication._protocol(route))
        pending = protocol and protocol['pending']
        target_path = publication.BASE+'publications/'+publication_id+'/state.json'
        if pending is None:
            target = publication._json(root,package,target_path)
            result = publication._result(target)
            current = publication._json(root,package,publication.ACTIVE)
            if not protocol or not any(row['publication_id'] == publication_id for row in current['events']):
                raise publication.IntakeError('publication_not_committed')
            return result
        if pending['publication_id'] != publication_id or pending['intent_digest'] != publication._hash(publication.canonical_json(saved)):
            raise publication.IntakeError('pending_intent_mismatch')
        if protocol['committed'] != saved['core']['old_cut'] or protocol['generation'] != saved['core']['old_generation']:
            raise publication.IntakeError('stale_publication_cut')
        from .continuity import _active_workers, ack_scope, context_binding, package_documents, scope_gaps
        from .policy import write_roles
        roles = write_roles(root) | {route.get('write_agent')}
        if saved['ack_request'] is not None and any(row['agent_type'] in roles for row in _active_workers(root).values()):
            raise publication.IntakeError('writer_quiescence_required')
        revision = route['context']['revision']
        old_revision = saved['core']['scope_revision']
        ack = route['context']['last_ack']
        if revision != old_revision and not (saved['ack_request'] and revision == old_revision+1 and ack and ack['operation_id'] == saved['ack_request']['operation_id']):
            raise publication.IntakeError('stale_scope_revision')
        for target,raw,boundary in [('change-spec.yaml',saved['spec'].encode(),'spec'), ('requirements.md',saved['requirements'].encode(),'requirements')]:
            if saved['ack_request'] is not None:
                publication._put(root,route,package,target,raw,saved['old_files'][target])
            elif publication._hash(publication._raw(root,package,target)) != saved['old_files'][target]:
                raise publication.IntakeError('recovery_conflict')
            publication._boundary(boundary)
        protocol['pending']['phase']='documents'
        route = publication._cursor(root,route,protocol)
        if saved['ack_request'] is not None:
            route = ack_scope(root,saved['ack_request'])
        if scope_gaps(root,route):
            raise publication.IntakeError('scope_sync_required')
        publication._boundary('ack')
        binding = context_binding(root,route)
        documents = package_documents(root,route)
        a = publication.digest({'ack':route['context']['last_ack'],'mirror':documents['state'].get('scope_ack')},'native-ack-v1')
        bindings = {'D':saved['core']['D'],'S':binding['spec_digest'],'R':binding['requirements_digest'],'A':a,'C':binding['digest']}
        old = saved['old_state']
        previous = {key:old[key] for key in ('identity','events','rounds','withdrawn')} if old else None
        reduced = publication.reduce_intake(previous,saved['event'],publication.NativeIntakeContext(
            identity=publication.native_identity(root,route), request_digest=saved['core']['request_digest'],
            publication_id=publication_id, at=saved['at'],
            max_rounds=(projection['input']['policy'].get('question_limits') or {}).get('max_question_rounds'),
            native_event_digest=(saved['core']['event_digest'] if saved['event']['kind']=='native_decision' else None),
            rebind_epoch=bool(old and publication._epoch_rebind(route,old['identity']))))
        rounds, withdrawn = reduced['rounds'], reduced['withdrawn']
        assessment = publication.assess_readiness(documents['spec'],projection,{**projection['input']['policy'],'rounds':rounds})
        from .intake_decisions import current_choice, apply_choice
        choice = current_choice(route,projection,reduced['events'],bindings['C'])
        assessment = apply_choice(assessment,choice if choice is None or choice['R']==bindings['R'] else None)
        target = {'version':1,'publication_id':publication_id,'generation':protocol['generation']+1,
                  'identity':publication.native_identity(root,route),'bindings':bindings,'projection':projection,
                  'assessment':assessment,'rounds':rounds,'withdrawn':withdrawn,
                  'events':reduced['events']}
        target_raw = publication.canonical_json(target)
        if len(target_raw)>publication.MAX_RETAINED_BYTES:
            raise publication.IntakeError('budget_exhausted')
        publication._put(root,route,package,target_path,target_raw,publication.ZERO)
        publication._boundary('target_state')
        protocol['pending'].update(phase='state_prepared',target_M=publication._hash(target_raw),target_state_ref=target_path)
        route = publication._cursor(root,route,protocol)
        publication._put(root,route,package,publication.ACTIVE,target_raw,saved['old_files'][publication.ACTIVE])
        publication._boundary('state')
        # Native context excludes cursors; live files/source/ACK must still match this target.
        if context_binding(root,route)['digest'] != bindings['C'] or scope_gaps(root,route):
            raise publication.IntakeError('context_changed_during_publication')
        publication._inputs(root,route,projection['input'],publication._raw(root,package,'requirements.md'))
        if publication._hash(publication._raw(root,package,publication.ACTIVE)) != publication._hash(target_raw):
            raise publication.IntakeError('state_changed_during_publication')
        result = publication._result(target)
        protocol.update(generation=target['generation'],committed=result['cut'],pending=None)
        publication._cursor(root,route,protocol)
        publication._boundary('commit')
        return result
    except publication.IntakeError:
        raise
    except (ValueError,OSError,KeyError,TypeError) as error:
        raise publication.IntakeError('intake_recovery_unavailable') from error


def decide_intake(root, *, decision, event_id, expected_cut_digest, expected_state_digest,
                  expected_draft_digest, expected_source_digest):
    """Explicit current native owner action, never an imported yes/human attestation.

    A caller must have actual owner delegation for this substantive choice. No
    prompt, document, scope ACK or saved principal field invokes this operation.
    """
    from .intake_decisions import valid_event, validate_stamp
    route = publication._owned(root)
    if route.get('status') in ('completed','cancelled'):
        raise publication.IntakeError('native_decision_owner_required')
    event = {'id':event_id,'kind':'native_decision','decision':decision}
    if not valid_event(event) or any(not publication._hex(value) for value in
            (expected_cut_digest,expected_state_digest,expected_draft_digest,expected_source_digest)):
        raise publication.IntakeError('invalid_native_decision')
    protocol = publication.copy.deepcopy(publication._protocol(route))
    if not protocol or not protocol['committed']:
        raise publication.IntakeError('native_decision_draft_required')
    package = publication._package(root,route)
    prior = protocol.get('native_decision')
    if prior is not None and prior['event']['id'] == event_id:
        validate_stamp(prior)
        if (prior['event'] != event or prior['D'] != expected_draft_digest or prior['R'] != expected_source_digest
                or prior['cut'] != expected_cut_digest or prior['state'] != expected_state_digest):
            raise publication.IntakeError('decision_event_collision')
        if prior['principal'] != route['session_id'] or prior['identity'] != publication.native_identity(root,route):
            raise publication.IntakeError('native_decision_owner_required')
    else:
        if protocol['pending'] is not None:
            raise publication.IntakeError('another_publication_pending')
        observed = publication.read_intake_cut(root)
        cut = observed['cut']
        if (publication.cut_digest(cut) != expected_cut_digest or cut['M'] != expected_state_digest
                or cut['D'] != expected_draft_digest or cut['R'] != expected_source_digest):
            raise publication.IntakeError('stale_native_decision')
        active = publication._json(root,package,publication.ACTIVE)
        if any(row['id']==event_id for row in active['events']):
            raise publication.IntakeError('decision_event_collision')
        prior = {'version':1,'principal':route['session_id'],'identity':publication.native_identity(root,route),
                 'D':cut['D'],'R':cut['R'],'P':publication.native_policy(root)['digest'],'C':cut['C'],
                 'cut':expected_cut_digest,'state':expected_state_digest,'event':event,'at':publication.now_utc()}
        validate_stamp(prior)
        protocol['native_decision'] = prior
        publication._cursor(root,route,protocol)
        publication._boundary('decision_admitted')
    from .continuity import context_binding, scope_gaps
    current_route = publication._owned(root)
    if scope_gaps(root,current_route) or context_binding(root,current_route)['digest'] != prior['C']:
        raise publication.IntakeError('stale_native_decision')
    data = publication._json(root,package,publication.BASE+'versions/'+prior['D']+'.json')
    requirements = publication._raw(root,package,'requirements.md').decode()
    if publication._hash(requirements.encode()) != prior['R'] or publication.native_policy(root)['digest'] != prior['P']:
        raise publication.IntakeError('stale_native_decision')
    return publication._prepare_intake(root,{'snapshot':data,'requirements':requirements,'event':event},
                           expected_cut_digest,expected_state_digest,native=True)
