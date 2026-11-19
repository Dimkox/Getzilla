"""Finite retirement on the existing protected result/outbox and registered UDS.

Local erasure, ephemeral disposal and a receiver observation are distinct facts.
Unknown delivery/retirement never permits an automatic mutation retry.
"""
import json
import secrets
import time

import httpx

from .access_authority import AccessError, _pairs
from .access_release import _remaining_bounds
from .contracts import canonical_digest, canonical_json

CONTRACT = 'factory-native-result-retirement/v1'
POSTCONDITION = 'factory-result-retirement-postcondition/v1'
FIELDS = ('operation_id', 'request_digest', 'envelope_digest', 'retirement_request_digest')


def request_identity(metadata):
    return {field: metadata[field] for field in FIELDS}


def postcondition(metadata):
    return canonical_digest({'contract': POSTCONDITION, **request_identity(metadata)})


def _operator(service, session, metadata):
    actor = service._authority.actor(session)
    if actor.kind != 'operator' or 'factory:access-admin' not in actor.scopes:
        raise AccessError('access_denied')
    if metadata is None:
        return actor.actor_id
    scope = metadata['scope']
    with service._authority._source:
        _snapshot, record, _principal = service._authority._current(session)
        allowed = (record['tenant_id'] == scope['tenant_id']
            and (scope['project_id'], scope['repository_id']) in record['_projects']
            and ('*' in actor.repositories or scope['repository_id'] in actor.repositories))
    if not allowed:
        # Unknown and foreign scoped results have the same opaque outcome.
        raise AccessError('retirement_unavailable')
    return actor.actor_id


def _metadata(service, envelope, deadline):
    if (type(envelope) is not str or len(envelope) != 64
            or any(c not in '0123456789abcdef' for c in envelope)):
        raise AccessError('invalid_access_request')
    try:
        with service._store._transaction(**_remaining_bounds(deadline)) as cursor:
            cursor.execute('SELECT factory.access_retirement_metadata_v1(%s)', (envelope,))
            return cursor.fetchone()[0]
    except AccessError:
        raise
    except Exception:
        raise AccessError('retirement_unavailable') from None


def _recipient(service, session, metadata, deadline, *, observation):
    try:
        _operator(service, session, metadata)
        scope = metadata['scope']
        with service._authority._source:
            snapshot, _record, _principal = service._authority._current(session)
            destination = snapshot.destinations.get(scope['destination_id'])
            current = (destination is not None
                and destination['revision'] == scope['destination_revision']
                and all(destination[key] == scope[key] for key in ('tenant_id', 'project_id', 'repository_id')))
        client = service._destinations.get(scope['destination_id'])
        if not current or client is None or metadata['destination_identity'] != {
                'kind': 'uds', 'device': client._socket_identity[0], 'inode': client._socket_identity[1]}:
            return None
        return _request(client, metadata, deadline, observation=observation)
    except Exception:
        return None


def _request(client, metadata, deadline, *, observation):
    client._revalidate_socket()
    path = '/v1/native-result-retirements'
    method = 'GET' if observation else 'POST'
    if observation:
        path += '/' + metadata['retirement_request_digest']
    arguments = {} if observation else {'json': {'contract': CONTRACT, **request_identity(metadata)}}
    headers = {'Authorization': 'Bearer ' + client._token,
        'Idempotency-Key': 'factory-retirement:' + metadata['retirement_request_digest'],
        'X-Operation-ID': metadata['operation_id']}
    remaining = min(client._timeout, deadline - time.monotonic())
    if remaining <= 0:
        return None
    try:
        with client._client() as transport, transport.stream(method, path, headers=headers,
                timeout=httpx.Timeout(remaining), **arguments) as response:
            raw = bytearray()
            for block in response.iter_bytes():
                if len(raw) + len(block) > 4096 or time.monotonic() >= deadline:
                    return None
                raw.extend(block)
            client._revalidate_socket()
            if response.status_code != 200 or response.headers.get('content-type') != 'application/json':
                return None
            body = json.loads(raw, object_pairs_hook=_pairs)
            if (type(body) is not dict or set(body) != {'status', 'postcondition_digest', *FIELDS}
                    or any(body[field] != metadata[field] for field in FIELDS)
                    or body['status'] != 'retired' or body['postcondition_digest'] != postcondition(metadata)):
                return None
            return body['postcondition_digest']
    except (httpx.HTTPError, ValueError, UnicodeError):
        return None


def _finish(service, metadata, receipt, deadline):
    try:
        with service._store._transaction(**_remaining_bounds(deadline)) as cursor:
            cursor.execute('SELECT factory.observe_access_retirement_v1(%s,%s,%s,%s)',
                (metadata['envelope_digest'], metadata['retirement_claim'],
                 'confirmed' if receipt is not None else 'unknown', receipt))
        return receipt is not None
    except Exception:
        return False


def _view(metadata, ephemeral=None, *, confirmed=None):
    return {'local_retired': metadata['local_retired'], 'ephemeral_retired': ephemeral,
        'recipient': 'confirmed' if (metadata['retirement_state'] == 'confirmed' if confirmed is None else confirmed)
            else 'unknown', 'operation_id': metadata['operation_id'],
        'retirement_request_digest': metadata['retirement_request_digest'],
        'retention_profile': metadata.get('retention_profile'), 'due_at': metadata.get('due_at'),
        'cleanup_delay_seconds': metadata.get('cleanup_delay_seconds'), 'clock_valid': metadata.get('clock_valid')}


def retire(service, session, envelope, *, reason):
    if type(reason) is not str or reason not in {'source_deleted', 'retention_expired', 'operator_retire'}:
        raise AccessError('invalid_access_request')
    deadline = time.monotonic() + 2
    _operator(service, session, None)
    metadata = _metadata(service, envelope, deadline)
    actor = _operator(service, session, metadata)
    try:
        with service._store._transaction(**_remaining_bounds(deadline)) as cursor:
            cursor.execute('SELECT factory.retire_access_result_v1(%s,%s,%s,%s,%s)',
                (envelope, canonical_json(metadata['scope']).decode(), actor, reason, secrets.token_hex(32)))
            claimed = cursor.fetchone()[0]
    except Exception:
        # A lost COMMIT is not retry permission or evidence of local erasure.
        return {'local_retired': None, 'ephemeral_retired': None, 'recipient': 'unknown',
            'operation_id': metadata['operation_id'], 'retirement_request_digest': None}
    ephemeral = service._retire_dependencies(tuple(claimed['dependency_digests']))
    if not claimed['dispatch_allowed']:
        return _view(claimed, ephemeral)
    receipt = _recipient(service, session, claimed, deadline, observation=False)
    confirmed = _finish(service, claimed, receipt, deadline)
    return _view(claimed, ephemeral, confirmed=confirmed)


def observe(service, session, envelope):
    deadline = time.monotonic() + 2
    _operator(service, session, None)
    metadata = _metadata(service, envelope, deadline)
    _operator(service, session, metadata)
    if metadata['retirement_state'] is None:
        return _view(metadata)
    ephemeral = service._retire_dependencies(tuple(metadata['dependency_digests']))
    if metadata['retirement_state'] == 'confirmed':
        return _view(metadata, ephemeral)
    receipt = _recipient(service, session, metadata, deadline, observation=True)
    return _view(metadata, ephemeral, confirmed=_finish(service, metadata, receipt, deadline))


def expire_due(service):
    """Existing lifecycle tick: only originally opted-in expired owned results."""
    if not service._automatic_retention:
        return
    deadline = time.monotonic() + 2
    try:
        with service._store._transaction(**_remaining_bounds(deadline)) as cursor:
            cursor.execute("SELECT trim(o.envelope_digest) FROM factory.next_model_request_outbox_v1 o "
                "JOIN factory.result_sources_v1 s USING(envelope_digest) "
                "WHERE o.retrieval_retention_profile='factory.ephemeral-retrieval162/v1' "
                "AND (clock_timestamp()>=o.retrieval_retire_after OR clock_timestamp()<o.retrieval_capture_at) "
                "AND (s.payload_retired_at IS NULL OR o.retirement_state IN ('sending','unknown')) "
                "ORDER BY s.payload_retired_at IS NOT NULL, "
                "COALESCE(o.retirement_last_observed_at,o.retrieval_retire_after),o.request_digest LIMIT 8")
            envelopes = tuple(row[0] for row in cursor.fetchall())
        for envelope in envelopes:
            metadata = _metadata(service, envelope, deadline)
            if not metadata['local_retired']:
                with service._store._transaction(**_remaining_bounds(deadline)) as cursor:
                    cursor.execute('SELECT factory.expire_access_result_v1(%s,%s)', (envelope, secrets.token_hex(32)))
                    metadata = cursor.fetchone()[0]
                observation = not metadata['dispatch_allowed']
            else:
                observation = True
            service._retire_dependencies(tuple(metadata['dependency_digests']))
            receipt = _lifecycle_recipient(service, metadata, deadline, observation=observation)
            _finish(service, metadata, receipt, deadline)
    except Exception:
        # No inferred deletion, renewed deadline or mutation retry on outage.
        # A following tick can rederive due/local facts; claimed stages are GET only.
        service.last_error = 'retrieval_retention_unavailable'
        return


def _lifecycle_recipient(service, metadata, deadline, *, observation):
    try:
        scope = metadata['scope']
        receiver = service._retention_receiver(scope['destination_id'])
        if receiver._expected != request_identity(metadata):
            return None
        service._authority._live()
        with service._authority._source:
            destination = service._authority._snapshot.destinations.get(scope['destination_id'])
            if (destination is None or destination['revision'] != scope['destination_revision']
                    or any(destination[key] != scope[key] for key in ('tenant_id','project_id','repository_id'))):
                return None
        client = service._destinations[scope['destination_id']]
        if metadata['destination_identity'] != {'kind': 'uds', 'device': client._socket_identity[0],
                'inode': client._socket_identity[1]}:
            return None
        return _request(client, metadata, deadline, observation=observation)
    except Exception:
        return None
