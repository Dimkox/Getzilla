"""Closed, inventory-bound OSV query transcripts; no network or authority here."""
from __future__ import annotations

import hashlib
import io
import json
import math
import re
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from .security_data import (OSV_ECOSYSTEMS, OSV_QUERY_SOURCE, SecurityDataError, _archive_census, _clock,
                            _json, _timestamp, osv_aliases, osv_coverage)

SOURCE_ID = OSV_QUERY_SOURCE
QUERY_URL = 'https://api.osv.dev/v1/querybatch'
DETAIL_URL = 'https://api.osv.dev/v1/vulns/'
MAX_QUERY_OBJECTS = 4096
QUERY_BATCH = 500
MAX_OBJECT_PAGES = 32
MAX_PAGE_REQUESTS = 128
MAX_DETAIL_FETCHES = 300
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_TRANSCRIPT_BYTES = 64 * 1024 * 1024
MAX_SECONDS = 180
MAX_TOKEN_BYTES = 4096
MAX_EXCHANGES = MAX_PAGE_REQUESTS + MAX_DETAIL_FETCHES


@dataclass(frozen=True)
class QueryResponse:
    method: str
    requested_url: str
    request: bytes
    body: bytes
    status: int
    final_url: str


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('utf-8')


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: Any) -> str:
    return sha(canonical(value))


def _path(value: Any) -> bool:
    return (type(value) is str and 0 < len(value) <= 4096 and '\\' not in value
            and not any(ord(c) < 32 for c in value)
            and all(part not in {'', '.', '..'} for part in value.split('/')))


def _hex(value: Any) -> bool:
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def portable_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    """Project physical custody out of source scope, not out of final local proof."""
    fields = {'schema_version', 'complete', 'selection', 'policy_sha256', 'policy_input', 'objects', 'inputs'}
    if (type(inventory) is not dict or set(inventory) != fields or inventory['schema_version'] != 1
            or type(inventory['schema_version']) is not int or inventory['complete'] is not True
            or inventory['selection'] != 'bounded-physical-source-with-explicit-exclusions'
            or not _hex(inventory['policy_sha256'])):
        raise SecurityDataError('query inventory proof is incomplete or unsupported')
    objects, inputs = inventory['objects'], inventory['inputs']
    if (type(objects) is not list or not 0 < len(objects) <= MAX_QUERY_OBJECTS
            or type(inputs) is not list or len(inputs) > 4096):
        raise SecurityDataError('query inventory is absent or exceeds its bound')
    projected_inputs = []
    for row in inputs:
        if (type(row) is not dict or not {'path', 'sha256', 'mode'} <= set(row)
                or set(row) - {'path', 'sha256', 'mode', 'identity_sha256'} or not _path(row['path'])
                or not _hex(row['sha256']) or type(row['mode']) is not int or not 0 <= row['mode'] <= 0o777):
            raise SecurityDataError('query inventory input is invalid')
        projected_inputs.append({key: row[key] for key in ('path', 'sha256', 'mode')})
    paths = {row['path'] for row in projected_inputs}
    if len(paths) != len(inputs):
        raise SecurityDataError('query inventory input is repeated')
    for row in objects:
        if (type(row) is not dict or set(row) != {'ecosystem', 'name', 'version', 'manifest'}
                or row['ecosystem'] not in OSV_ECOSYSTEMS or row['manifest'] not in paths
                or any(type(row[key]) is not str or not 0 < len(row[key]) <= 1024
                       or any(ord(c) < 32 for c in row[key]) for key in ('name', 'version'))):
            raise SecurityDataError('query inventory object is invalid')
    if len({_digest(row) for row in objects}) != len(objects):
        raise SecurityDataError('query inventory object is repeated')
    policy = inventory['policy_input']
    if policy is not None:
        if (type(policy) is not dict or not {'sha256', 'mode'} <= set(policy)
                or set(policy) - {'sha256', 'mode', 'identity_sha256'} or not _hex(policy['sha256'])
                or type(policy['mode']) is not int or not 0 <= policy['mode'] <= 0o777):
            raise SecurityDataError('query policy proof is invalid')
        policy = {key: policy[key] for key in ('sha256', 'mode')}
    return {'schema_version': 1, 'complete': True, 'selection': inventory['selection'],
            'policy_sha256': inventory['policy_sha256'], 'policy_input': policy,
            'objects': sorted(objects, key=lambda row: tuple(row[k] for k in ('ecosystem', 'name', 'version', 'manifest'))),
            'inputs': sorted(projected_inputs, key=lambda row: row['path'])}


def query_plan(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    from .known_vulns import normalize_name
    groups = {}
    for index, row in enumerate(inventory['objects']):
        key = row['ecosystem'], normalize_name(row['ecosystem'], row['name']), row['version']
        groups.setdefault(key, []).append(index)
    return [{'ecosystem': eco, 'name': name, 'version': version, 'objects': groups[(eco, name, version)]}
            for eco, name, version in sorted(groups)]


def _identifier(value: Any) -> str:
    if type(value) is not str or not 0 < len(value) <= 1024 or value in {'.', '..'}:
        raise SecurityDataError('query advisory identity is invalid')
    osv_aliases({'aliases': [value]})  # One native identifier rule, no URL/path syntax.
    return value


def check_deadline(deadline: float) -> None:
    if type(deadline) not in (int, float) or not math.isfinite(deadline) or time.monotonic() >= deadline:
        raise SecurityDataError('query acquisition deadline exceeded')


def _protocol(plan: list[dict[str, Any]], exchange: Callable) -> tuple[list[dict], dict[str, dict]]:
    hits, modified, pages = [], {}, 0
    for start in range(0, len(plan), QUERY_BATCH):
        pending = list(range(start, min(len(plan), start + QUERY_BATCH)))
        tokens, seen, counts = {}, {}, {}
        while pending:
            pages += 1
            if pages > MAX_PAGE_REQUESTS:
                raise SecurityDataError('query page request bound exceeded')
            queries = []
            for index in pending:
                counts[index] = counts.get(index, 0) + 1
                if counts[index] > MAX_OBJECT_PAGES:
                    raise SecurityDataError('query object page bound exceeded')
                item = plan[index]
                queries.append({'package': {'ecosystem': item['ecosystem'], 'name': item['name']},
                                'version': item['version'], **({'page_token': tokens[index]} if index in tokens else {})})
            answer = exchange('POST', QUERY_URL, canonical({'queries': queries}))
            if type(answer) is not dict or set(answer) != {'results'} or type(answer['results']) is not list or len(answer['results']) != len(pending):
                raise SecurityDataError('query response does not cover every submitted object')
            next_pending = []
            for index, result in zip(pending, answer['results']):
                if type(result) is not dict or set(result) - {'vulns', 'next_page_token'}:
                    raise SecurityDataError('query result is malformed or incomplete')
                vulns = result.get('vulns', [])
                if type(vulns) is not list or len(vulns) > MAX_DETAIL_FETCHES:
                    raise SecurityDataError('query detail census exceeds bound')
                for summary in vulns:
                    if type(summary) is not dict or set(summary) != {'id', 'modified'}:
                        raise SecurityDataError('query summary identity is incomplete')
                    identifier = _identifier(summary['id'])
                    stamp = summary['modified']
                    _timestamp(stamp)
                    if identifier in modified and modified[identifier] != stamp:
                        raise SecurityDataError('query summary modified identity is contradictory')
                    modified[identifier] = stamp
                    if len(modified) > MAX_DETAIL_FETCHES:
                        raise SecurityDataError('query detail census exceeds bound')
                    hits.append({'query_index': index, 'id': identifier})
                token = result.get('next_page_token')
                if token is not None:
                    if (type(token) is not str or not token or len(token.encode('utf-8')) > MAX_TOKEN_BYTES
                            or token in seen.setdefault(index, set())):
                        raise SecurityDataError('query continuation is invalid or repeated')
                    seen[index].add(token)
                    tokens[index] = token
                    next_pending.append(index)
            pending = next_pending
    records = {}
    for identifier in sorted(modified):
        record = exchange('GET', DETAIL_URL + identifier, b'')
        if (type(record) is not dict or record.get('id') != identifier
                or record.get('modified') != modified[identifier] or record.get('withdrawn')):
            raise SecurityDataError('query detail identity changed or is unavailable')
        _timestamp(record['modified'])
        osv_aliases(record)
        if (any(key in record and record[key] is not None and type(record[key]) is not str for key in ('summary', 'details'))
                or type(record.get('database_specific', {})) is not dict
                or type(record.get('severity', [])) is not list
                or any(type(row) is not dict or type(row.get('score', '')) is not str
                       or type(row.get('type', '')) is not str for row in record.get('severity', []))):
            raise SecurityDataError('query detail decision fields are malformed')
        # Apply the same strict native record contract to every queried ecosystem.
        # This validates data, never filters a positive verdict into absence.
        for ecosystem in {plan[hit['query_index']]['ecosystem'] for hit in hits if hit['id'] == identifier}:
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as archive:
                archive.writestr('record.json', canonical(record))
            osv_coverage(output.getvalue(), ecosystem)
        from .known_vulns import VulnerabilityError, _in_ranges, normalize_name
        for hit in (hit for hit in hits if hit['id'] == identifier):
            requested = plan[hit['query_index']]
            if not any(type(row.get('package')) is dict and row['package'].get('ecosystem') == requested['ecosystem']
                       and normalize_name(requested['ecosystem'], row['package'].get('name', '')) == requested['name']
                       for row in record.get('affected', [])):
                raise SecurityDataError('query detail does not identify the queried package')
            for row in record['affected']:
                package = row.get('package', {})
                if (package.get('ecosystem') == requested['ecosystem']
                        and normalize_name(requested['ecosystem'], package.get('name', '')) == requested['name']):
                    if type(row.get('database_specific', {})) is not dict:
                        raise SecurityDataError('query detail decision fields are malformed')
                    try:
                        # Validate all coverage with the frozen native guard.
                        # Its boolean is deliberately not a query-hit filter.
                        _in_ranges(requested['version'], row, ecosystem=requested['ecosystem'])
                    except VulnerabilityError:
                        raise SecurityDataError('query detail range coverage is unsupported or malformed') from None
        records[identifier] = record
    unique = {(hit['query_index'], hit['id']) for hit in hits}
    return [{'query_index': index, 'id': identifier} for index, identifier in sorted(unique)], records


def acquire_transcript(inventory: dict[str, Any], *, transport: Callable,
                       now: datetime | None = None, deadline: float | None = None) -> tuple[bytes, dict, dict]:
    """Capture exact qualified responses; a transport seam is not trusted JSON."""
    inventory = portable_inventory(inventory)
    plan = query_plan(inventory)
    ceiling = time.monotonic() + MAX_SECONDS
    if deadline is not None:
        check_deadline(deadline)
    deadline = ceiling if deadline is None else min(deadline, ceiling)
    check_deadline(deadline)
    started = _clock(now)
    members, exchanges, total = {}, [], 0

    def exchange(method, url, request):
        nonlocal total
        if len(request) > MAX_REQUEST_BYTES or len(exchanges) >= MAX_EXCHANGES:
            raise SecurityDataError('query request or exchange bound exceeded')
        check_deadline(deadline)
        remaining = min(MAX_RESPONSE_BYTES, MAX_TRANSCRIPT_BYTES - total - len(request))
        if remaining <= 0:
            raise SecurityDataError('query remaining body budget is insufficient before transport')
        response = transport(method, url, request, deadline, remaining)
        check_deadline(deadline)
        if (type(response) is not QueryResponse or response.method != method or response.requested_url != url
                or response.request != request or response.final_url != url or response.status != 200
                or type(response.status) is not int or type(response.body) is not bytes
                or not 0 < len(response.body) <= MAX_RESPONSE_BYTES):
            raise SecurityDataError('query transport lacks exact request or complete successful response')
        total += len(request) + len(response.body)
        if total > MAX_TRANSCRIPT_BYTES:
            raise SecurityDataError('query transcript aggregate body bound exceeded')
        ordinal = len(exchanges)
        request_name, response_name = f'requests/{ordinal:04}.json', f'responses/{ordinal:04}.json'
        members[request_name], members[response_name] = request, response.body
        exchanges.append({'method': method, 'url': url, 'final_url': response.final_url, 'status': response.status,
                          'request': request_name, 'response': response_name,
                          'request_sha256': sha(request), 'response_sha256': sha(response.body),
                          'request_size': len(request), 'response_size': len(response.body)})
        return _json(response.body)

    try:
        _protocol(plan, exchange)
        check_deadline(deadline)
        ended = _clock(now)
        if not 0 <= (ended - started).total_seconds() <= MAX_SECONDS:
            raise SecurityDataError('query UTC acquisition interval is unavailable or exceeds bound')
        metadata = {'schema_version': 1, 'source_id': SOURCE_ID, 'inventory': inventory,
                    'inventory_sha256': _digest(inventory), 'started_at_utc': started.isoformat(),
                    'completed_at_utc': ended.isoformat(), 'exchanges': exchanges}
        raw = canonical(metadata)
        if len(raw) > MAX_REQUEST_BYTES:
            raise SecurityDataError('query metadata exceeds bound')
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('transcript.json', raw)
            for name, body in members.items():
                archive.writestr(name, body)
        payload = output.getvalue()
        replay = validate_transcript(payload, expected_inventory=inventory)
        check_deadline(deadline)
        acquisition = {'last_verified_sync_utc': started.isoformat(), 'retrieval_kind': 'download',
                       'producer': 'synthetic-public-injected-osv-query-v1'}
        return payload, acquisition, replay['coverage']
    except (ValueError, KeyError, TypeError, RecursionError):
        raise SecurityDataError('query acquisition is incomplete or malformed') from None


def validate_transcript(payload: bytes, *, expected_inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    """Replay every raw exchange; metadata is an index, never a result assertion."""
    try:
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_TRANSCRIPT_BYTES + MAX_REQUEST_BYTES:
            raise SecurityDataError('query transcript payload exceeds bound')
        _archive_census(payload, max_members=1 + 2 * MAX_EXCHANGES,
                        max_expanded=MAX_TRANSCRIPT_BYTES + MAX_REQUEST_BYTES, max_directory=MAX_REQUEST_BYTES)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()
            if len(infos) > 1 + 2 * MAX_EXCHANGES or len({row.filename for row in infos}) != len(infos):
                raise SecurityDataError('query transcript member census is invalid')
            by_name = {row.filename: row for row in infos}
            if 'transcript.json' not in by_name or by_name['transcript.json'].file_size > MAX_REQUEST_BYTES:
                raise SecurityDataError('query transcript metadata is missing or exceeds bound')
            if sum(row.file_size for row in infos) > MAX_TRANSCRIPT_BYTES + MAX_REQUEST_BYTES:
                raise SecurityDataError('query transcript expanded aggregate exceeds bound')
            for row in infos:
                if (row.is_dir() or row.flag_bits & 1 or row.file_size > MAX_RESPONSE_BYTES
                        or row.external_attr >> 16 & 0o170000 not in {0, 0o100000}):
                    raise SecurityDataError('query transcript member is unsupported')
            metadata = _json(archive.read('transcript.json'))
            fields = {'schema_version', 'source_id', 'inventory', 'inventory_sha256',
                      'started_at_utc', 'completed_at_utc', 'exchanges'}
            if (set(metadata) != fields or type(metadata['schema_version']) is not int
                    or metadata['schema_version'] != 1 or metadata['source_id'] != SOURCE_ID):
                raise SecurityDataError('query transcript metadata schema is invalid')
            inventory = portable_inventory(metadata['inventory'])
            if inventory != metadata['inventory'] or _digest(inventory) != metadata['inventory_sha256']:
                raise SecurityDataError('query transcript inventory digest differs')
            if expected_inventory is not None and portable_inventory(expected_inventory) != inventory:
                raise SecurityDataError('query transcript does not cover the current policy and inventory')
            started, ended = _timestamp(metadata['started_at_utc']), _timestamp(metadata['completed_at_utc'])
            if not 0 <= (ended - started).total_seconds() <= MAX_SECONDS:
                raise SecurityDataError('query transcript acquisition interval is invalid')
            exchanges = metadata['exchanges']
            if type(exchanges) is not list or not 0 < len(exchanges) <= MAX_EXCHANGES:
                raise SecurityDataError('query transcript exchange census is invalid')
            expected_names = {'transcript.json'} | {f'{kind}/{i:04}.json' for i in range(len(exchanges))
                                                    for kind in ('requests', 'responses')}
            if set(by_name) != expected_names:
                raise SecurityDataError('query transcript closed membership differs')
            position, total = 0, 0

            def exchange(method, url, request):
                nonlocal position, total
                if position >= len(exchanges) or len(request) > MAX_REQUEST_BYTES:
                    raise SecurityDataError('query transcript has a missing exchange')
                row = exchanges[position]
                request_name, response_name = f'requests/{position:04}.json', f'responses/{position:04}.json'
                position += 1
                fields = {'method', 'url', 'final_url', 'status', 'request', 'response', 'request_sha256',
                          'response_sha256', 'request_size', 'response_size'}
                if (type(row) is not dict or set(row) != fields or row['method'] != method or row['url'] != url
                        or row['final_url'] != url or type(row['status']) is not int or row['status'] != 200
                        or row['request'] != request_name or row['response'] != response_name
                        or type(row['request_size']) is not int or row['request_size'] != len(request)
                        or row['request_sha256'] != sha(request)
                        or by_name[request_name].file_size != len(request)
                        or type(row['response_size']) is not int or not 0 < row['response_size'] <= MAX_RESPONSE_BYTES
                        or by_name[response_name].file_size != row['response_size']):
                    raise SecurityDataError('query transcript request or response binding differs')
                total += len(request) + row['response_size']
                if total > MAX_TRANSCRIPT_BYTES:
                    raise SecurityDataError('query transcript remaining body budget is insufficient')
                if archive.read(request_name) != request:
                    raise SecurityDataError('query transcript request bytes differ')
                body = archive.read(response_name)
                if sha(body) != row['response_sha256']:
                    raise SecurityDataError('query transcript response digest differs')
                return _json(body)

            plan = query_plan(inventory)
            hits, records = _protocol(plan, exchange)
            if position != len(exchanges):
                raise SecurityDataError('query transcript has an unconsumed exchange')
            return {'inventory_sha256': metadata['inventory_sha256'], 'started_at_utc': started.isoformat(),
                    'completed_at_utc': ended.isoformat(), 'plan': plan, 'hits': hits, 'records': records,
                    'coverage': {'scopes': sorted({row['ecosystem'] for row in plan}), 'complete': True,
                                 'record_count': len(records), 'schema': 'osv-query-1'}}
    except (OSError, ValueError, KeyError, TypeError, RecursionError, RuntimeError, zipfile.BadZipFile):
        raise SecurityDataError('query transcript is incomplete or malformed') from None
