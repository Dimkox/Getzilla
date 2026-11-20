"""Explicit current-owner fixed public-study intent, separate from live execution.

An operation ref is not a source lease or live resource. Only the actual owned
supervisor can supply the latter, before any native import or model stage.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
import time

from .. import state
from ..continuity import scope_gaps
from ..receipts import get_receipt, write_receipt
from .contracts import digest, hex_digest, label
from .evaluation_inputs import checked_relative
from .evaluation_inputs_io import _json
from .public_review_inputs import _require
from . import public_review_witness as reviews
from .study_artifacts import snapshot_study_export, check_study_export
from .study_resources import RESOURCE_PROFILE_SHA256, resource_profile

INSPECT = 'inspect_public_artifacts'
RANK = 'rank_public_study'
KINDS = {INSPECT: 'retrieval-public-inspect-operation', RANK: 'retrieval-public-rank-operation'}
INSPECT_STAGES = frozenset({'inspect_native_import', 'inspect_tokenizer', 'inspect_graph', 'inspect_windows', 'inspect_runtime', 'inspect_release'})
RANK_STAGES = frozenset({'rank_encode', 'rank_score', 'rank_release'})
_ISSUER = object()


@dataclass(frozen=True)
class PublicStudyOperationProjection:
    root: Path
    operation: str
    operation_digest: str
    image_id: str
    docker_executable: str
    docker_sha256: str
    daemon_id: str
    model_root: Path
    software_root: Path
    worker_root: Path
    worker_sha256: str
    cpu_ids: tuple[int, int]
    resource_profile_sha256: str
    conditions_sha256: str
    registration_sha256: str
    phase_a_sha256: str
    phase_b_sha256: str | None
    artifact_files: tuple
    software_files: tuple
    worker_files: tuple
    hard_timeout_seconds: int
    execution_intent: str
    execution_label: str
    original_deadline: float | None = None


@dataclass(frozen=True)
class PublicStudySourceCheckpoint:
    deadline: float
    batches: tuple[int, ...]


@dataclass(frozen=True)
class PublicStudyInputs:
    dataset: tuple
    configuration: dict
    model_facts: tuple
    inspection_manifest: dict | None
    runtime_registration: dict
    dataset_digest: str
    artifact_manifest_digest: str


@dataclass(frozen=True)
class _Composition:
    profile: str
    reviews: object
    conditions: object = None
    worker_sources: tuple | None = None
    docker_path: str = '/usr/bin/docker'


_PRODUCTION = _Composition('public-research162/v1', reviews._PRODUCTION)


class PublicStudyOperationRef:
    __slots__ = ('_issuer', '_root', '_composition', '_receipt_sha256', '_a', '_b', '_conditions',
                 '_exports', '_request', '_registration', '_docker', '_projection')

    def __new__(cls, *args, **kwargs):
        raise TypeError('explicit current-owner public study operation required')

    def __setattr__(self, name, value):
        raise AttributeError('public study operation is immutable')

    def __reduce__(self):
        raise TypeError('public study operation cannot be serialized')


def operation_status():
    return {'execution_enabled': False, 'reason': 'explicit_current_operation_and_live_resource_required',
            'native_imported': False, 'ranking_permitted': False}


def _condition_check(reference, composition):
    from .research_use_conditions import check_public_research_use, _check_public_research_use
    if composition is _PRODUCTION:
        return check_public_research_use(reference)
    _require(composition.conditions is not None, 'public_study_conditions_unavailable')
    return _check_public_research_use(reference, composition.conditions)


def _pins(rows):
    _require(type(rows) in (tuple, list) and len(rows) <= 16384, 'public_study_inventory_unavailable')
    result, seen = [], set()
    for row in rows:
        _require(type(row) in (tuple, list) and len(row) == 3 and type(row[0]) is str
                 and type(row[1]) is int and row[1] >= 0 and hex_digest(row[2]))
        checked_relative(row[0])
        _require(row[0] not in seen)
        seen.add(row[0])
        result.append(tuple(row))
    return tuple(result)


def _worker_files(root, composition):
    if composition is _PRODUCTION:
        from .study_worker_inventory import worker_source_files
        return worker_source_files(root)
    _require(type(composition.worker_sources) is tuple and composition.worker_sources)
    result = []
    with reviews.native_root(root) as anchor:
        for source, exported in composition.worker_sources:
            raw = anchor.read(source, source=True)
            result.append((exported, len(raw), reviews.sha(raw)))
    return tuple(result)


def _docker(path, expected_sha256, deadline, *, expected_identity=None):
    _require(type(path) is str and type(expected_sha256) is str and hex_digest(expected_sha256))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                 and not before.st_mode & 0o022 and before.st_size <= 64 * 1048576,
                 'public_study_docker_unavailable')
        identity = reviews._identity(before)
        _require(reviews._identity(os.stat(path, follow_symlinks=False)) == identity)
        if expected_identity is not None:
            _require(identity == expected_identity, 'public_study_docker_unavailable')
        else:
            hasher, total = hashlib.sha256(), 0
            while True:
                _require(time.monotonic() < deadline, 'public_study_deadline')
                block = os.read(descriptor, min(65536, 64 * 1048576 + 1 - total))
                if not block:
                    break
                total += len(block)
                _require(total <= 64 * 1048576)
                hasher.update(block)
            _require(hasher.hexdigest() == expected_sha256, 'public_study_docker_unavailable')
        _require(reviews._identity(os.fstat(descriptor)) == identity
                 and reviews._identity(os.stat(path, follow_symlinks=False)) == identity,
                 'public_study_docker_unavailable')
        return identity
    finally:
        os.close(descriptor)


def _runtime(request, conditions, root, composition, *, operation_digest, registration_sha256, worker_files):
    _require(type(request) is dict and set(request) == {'schema_version', 'kind', 'operation', 'phase_a_sha256',
        'phase_b_sha256', 'conditions_sha256', 'artifact_manifest_sha256', 'graph_observations', 'runtime'})
    _require(type(request['schema_version']) is int and request['schema_version'] == 1
             and request['kind'] == 'public-study-operation/v1' and request['operation'] in KINDS)
    runtime = request['runtime']
    required = {'inference_image_id', 'inspection_image_id', 'docker_executable', 'docker_sha256', 'daemon_id',
        'model_root', 'software_root', 'worker_root', 'artifact_files', 'software_files', 'worker_files',
        'cpu_ids', 'hard_timeout_seconds', 'resource_profile_sha256', 'base_image_digest', 'recipe_digest'}
    _require(type(runtime) is dict and set(runtime) == required)
    for field in ('inference_image_id', 'inspection_image_id'):
        value = runtime[field]
        _require(type(value) is str and value.startswith('sha256:') and hex_digest(value[7:]))
    _require(runtime['docker_executable'] == composition.docker_path and hex_digest(runtime['docker_sha256'])
             and label(runtime['daemon_id']) and runtime['resource_profile_sha256'] == RESOURCE_PROFILE_SHA256
             and all(hex_digest(runtime[key]) for key in ('base_image_digest', 'recipe_digest')))
    _require(type(runtime['cpu_ids']) is list and len(runtime['cpu_ids']) == 2
             and all(type(value) is int and 0 <= value <= 1048575 for value in runtime['cpu_ids'])
             and sorted(set(runtime['cpu_ids'])) == runtime['cpu_ids'])
    _require(type(runtime['hard_timeout_seconds']) is int
             and 1 <= runtime['hard_timeout_seconds'] <= resource_profile()['hard_timeout_max_seconds'])
    _require(conditions['preparation_state'] == 'extracted-software-held'
             and Path(conditions['root']) == Path(root)
             and request['conditions_sha256'] == conditions['conditions_sha256']
             and request['artifact_manifest_sha256'] == conditions['artifact_manifest_sha256'],
             'public_study_conditions_unavailable')
    artifact_files, software_files = _pins(conditions['artifact_files']), _pins(conditions['software_files'])
    _require(_pins(runtime['artifact_files']) == artifact_files and _pins(runtime['software_files']) == software_files
             and _pins(runtime['worker_files']) == worker_files)
    for field in ('model_root', 'software_root', 'worker_root'):
        checked_relative(runtime[field])
        _require(runtime[field].startswith('.getzilla/runtime/'), 'public_study_export_unavailable')
    _require(len({runtime[field] for field in ('model_root', 'software_root', 'worker_root')}) == 3)
    from .public_study_storage import fixed_export_attempt
    fixed_export_attempt(runtime)
    expected_image = conditions['image']['config']['digest']
    _require(runtime['inspection_image_id'] == expected_image and runtime['inference_image_id'] == expected_image,
             'public_study_unregistered_image')
    expected_base = conditions['image']['selected_manifest_digest'] if composition is _PRODUCTION else expected_image
    _require(runtime['base_image_digest'] == expected_base.removeprefix('sha256:'), 'public_study_unregistered_image')
    entries = {name: sha for name, _, sha in worker_files}
    entry = 'getzilla/retrieval/study_worker_entry.py'
    _require(entry in entries, 'public_study_worker_unavailable')
    image = runtime['inspection_image_id' if request['operation'] == INSPECT else 'inference_image_id']
    return PublicStudyOperationProjection(Path(root), request['operation'], operation_digest, image,
        runtime['docker_executable'], runtime['docker_sha256'], runtime['daemon_id'],
        Path(root) / runtime['model_root'], Path(root) / runtime['software_root'], Path(root) / runtime['worker_root'],
        entries[entry], tuple(runtime['cpu_ids']), RESOURCE_PROFILE_SHA256, request['conditions_sha256'],
        registration_sha256, request['phase_a_sha256'], request['phase_b_sha256'], artifact_files, software_files,
        worker_files, runtime['hard_timeout_seconds'], '', '')


def _review_current(reference, composition):
    _require(type(reference) is reviews.OperatorWitnessedPublicReviewedInputs
             and getattr(reference, '_issuer', None) is reviews._ISSUER and reference._profile == composition.reviews.profile,
             'public_study_reviews_unavailable')
    capture = reviews._Capture(reference._root)
    receipt = get_receipt(capture.root, capture.route['route_id'], reviews.KIND)
    _require(receipt is not None and digest(receipt) == reference._receipt_digest, 'public_study_reviews_unavailable')
    data = receipt['details']
    _require(data['profile'] == composition.reviews.profile and data['context'] == capture.context
             and data['physical_root'] == list(capture.physical_root)
             and data['source_binding'] == list(capture.source_binding)
             and data['policy_sha256'] == capture.policy and data['module_manifest_sha256'] == capture.manifest)
    capture.dependencies = {row['path']: row for row in data['dependencies']}
    capture.recheck()
    return data


def _holdout_claim(root, route, label_value, operation_digest):
    from ..execution_store import load_registry
    records = load_registry(Path(root))['records'].values()
    matches = [record for record in records if record['input']['display']['label'] == label_value]
    _require(len(matches) <= 1 and all(record['operation_id'] == operation_digest for record in matches),
             'public_study_holdout_already_claimed')


def _issue(capture, receipt, composition, phase_a, phase_b, conditions, exports, request, registration, docker, projection):
    reference = object.__new__(PublicStudyOperationRef)
    for key, value in (('_issuer', _ISSUER), ('_root', str(capture.root)), ('_composition', composition),
        ('_receipt_sha256', digest(receipt)), ('_a', phase_a), ('_b', phase_b), ('_conditions', conditions),
        ('_exports', tuple(exports)), ('_request', request), ('_registration', registration),
        ('_docker', docker), ('_projection', projection)):
        object.__setattr__(reference, key, value)
    return reference


@state.serialized_task
def _register_public_study_operation(root, operation, registration_path, phase_a, conditions, phase_b, composition):
    _require(type(composition) is _Composition and (composition.profile != _PRODUCTION.profile or composition is _PRODUCTION))
    _require(operation in KINDS)
    a_facts = reviews._consume(phase_a, composition.reviews)
    capture = reviews._Capture(root)
    _require(Path(phase_a._root) == capture.root and not scope_gaps(capture.root, capture.route))
    condition_facts = _condition_check(conditions, composition)
    raw = capture.read(registration_path)
    request = _json(raw)
    registration = capture.dependencies[registration_path]
    _require(request['operation'] == operation and request['phase_a_sha256'] == phase_a._receipt_digest)
    if operation == INSPECT:
        _require(phase_b is None and request['phase_b_sha256'] is None)
    else:
        _require(phase_b is not None and hex_digest(request['phase_b_sha256']), 'public_study_inspection_required')
        from .public_study_inspection import consume_public_inspection
        facts = consume_public_inspection(phase_b, phase_a)
        _require(request['phase_b_sha256'] == facts['witness_sha256'])
    operation_digest = digest({'context': capture.context, 'source': capture.source_binding,
        'registration_sha256': registration['sha256'], 'operation': operation, 'conditions': condition_facts['conditions_sha256']})
    if composition is _PRODUCTION:
        from .public_study_graphs import graph_observations
        graph_observations(capture, request['graph_observations'], condition_facts['models'])
    else:
        _require(request['graph_observations'] is None)
    worker_files = _worker_files(root, composition)
    projection = _runtime(request, condition_facts, root, composition, operation_digest=operation_digest,
                          registration_sha256=registration['sha256'], worker_files=worker_files)
    from dataclasses import replace
    scientific = digest([a_facts['dataset'], a_facts['config_sha256']])
    intent = ('study162-holdout-' + scientific) if operation == RANK else ('study162-inspect-' + operation_digest)
    display = ('162holdout ' + scientific) if operation == RANK else ('162inspect ' + operation_digest)
    projection = replace(projection, execution_intent=intent, execution_label=display)
    if operation == RANK:
        from .public_study_inspection import public_inspection_deadline
        projection = replace(projection, original_deadline=public_inspection_deadline(phase_b, phase_a))
        _holdout_claim(root, capture.route, display, operation_digest)
    def recheck():
        capture.recheck()
        if operation == RANK:
            _require(public_inspection_deadline(phase_b, phase_a) == projection.original_deadline,
                     'public_study_original_deadline')
    recheck()
    docker = _docker(projection.docker_executable, projection.docker_sha256, capture.deadline)
    exports = []
    try:
        for field, pins in (('model_root', projection.artifact_files), ('software_root', projection.software_files),
                            ('worker_root', projection.worker_files)):
            exports.append(snapshot_study_export(root, request['runtime'][field], pins))
        details = {'state': 'active', 'assurance': reviews.ASSURANCE, 'profile': composition.profile,
            'statement': 'Current owner consents to this fixed public study operation; no human or security approval.',
            'context': capture.context, 'physical_root': list(capture.physical_root), 'source_binding': list(capture.source_binding),
            'policy_sha256': capture.policy, 'module_manifest_sha256': capture.manifest,
            'registration': registration, 'dependencies': list(capture.dependencies.values()),
            'operation': operation, 'operation_digest': operation_digest,
            'conditions_sha256': projection.conditions_sha256, 'request_digest': digest(request),
            'export_bindings': [snapshot.binding_digest for snapshot in exports], 'docker_identity': docker}
        previous = get_receipt(root, capture.route['route_id'], KINDS[operation])
        if previous is not None and previous['details']['context'] == capture.context:
            _require(previous['details'] == details, 'public_study_operation_conflict')
            receipt = previous
        else:
            recheck()
            write_receipt(root, KINDS[operation], 'observed', details=details,
                          expected_context=capture.context, interrupt_check=recheck)
            receipt = get_receipt(root, capture.route['route_id'], KINDS[operation])
        _require(receipt is not None and receipt['details'] == details)
        reference = _issue(capture, receipt, composition, phase_a, phase_b, conditions, exports,
                           request, registration, docker, projection)
        _check_public_study_operation(reference, composition)
        return reference
    except BaseException:
        for snapshot in exports:
            snapshot.close()
        raise


def register_public_study_operation(root, operation, registration_path, phase_a, conditions, phase_b=None):
    """Explicit current-owner intent; actual owned resources remain mandatory."""
    reviews.consume_public_reviews(phase_a)
    _require(Path(root).resolve() == Path(phase_a._root), 'public_study_operation_unavailable')
    _condition_check(conditions, _PRODUCTION)
    return _register_public_study_operation(root, operation, registration_path, phase_a, conditions, phase_b, _PRODUCTION)


def _check_public_study_operation(reference, composition):
    _require(type(reference) is PublicStudyOperationRef and getattr(reference, '_issuer', None) is _ISSUER
             and reference._composition is composition, 'public_study_operation_unavailable')
    capture = reviews._Capture(reference._root)
    projection = reference._projection
    receipt = get_receipt(capture.root, capture.route['route_id'], KINDS[projection.operation])
    _require(receipt is not None and digest(receipt) == reference._receipt_sha256)
    details = receipt['details']
    _require(details['state'] == 'active' and details['context'] == capture.context
             and details['physical_root'] == list(capture.physical_root)
             and details['source_binding'] == list(capture.source_binding)
             and details['policy_sha256'] == capture.policy and details['module_manifest_sha256'] == capture.manifest
             and details['request_digest'] == digest(reference._request)
             and not scope_gaps(capture.root, capture.route), 'public_study_operation_stale')
    _review_current(reference._a, composition)
    conditions = _condition_check(reference._conditions, composition)
    _require(conditions['conditions_sha256'] == projection.conditions_sha256
             and conditions['preparation_state'] == 'extracted-software-held')
    capture.dependencies = {row['path']: row for row in details['dependencies']}
    capture.recheck()
    _docker(projection.docker_executable, projection.docker_sha256, capture.deadline, expected_identity=reference._docker)
    _require([snapshot.binding_digest for snapshot in reference._exports] == details['export_bindings'])
    for snapshot in reference._exports:
        check_study_export(snapshot)
    if projection.operation == RANK:
        from .public_study_inspection import consume_public_inspection, public_inspection_deadline
        facts = consume_public_inspection(reference._b, reference._a)
        _require(public_inspection_deadline(reference._b, reference._a) == projection.original_deadline,
                 'public_study_original_deadline')
        _require(facts['witness_sha256'] == projection.phase_b_sha256)
        _holdout_claim(capture.root, capture.route, projection.execution_label, projection.operation_digest)
    else:
        _require(projection.original_deadline is None, 'public_study_original_deadline')
    return projection


def check_public_study_operation(reference):
    return _check_public_study_operation(reference, _PRODUCTION)


def check_public_study_source_cuts(reference, source_cuts):
    check_public_study_operation(reference)
    _require(type(source_cuts) is tuple and 1 <= len(source_cuts) <= 2)
    observed = []
    for pair in source_cuts:
        _require(type(pair) is tuple and len(pair) == 2)
        observed.append(reviews.check_reviewed_public_source_batch(reference._a, *pair))
    _require(len({row['batch'] for row in observed}) == len(observed))
    return PublicStudySourceCheckpoint(min(row['deadline'] for row in observed), tuple(sorted(row['batch'] for row in observed)))


def admit_public_study_stage(reference, live_resource_ref, stage, *, source_cuts=()):
    projection = check_public_study_operation(reference)
    expected = INSPECT_STAGES if projection.operation == INSPECT else (RANK_STAGES | (INSPECT_STAGES - {'inspect_release'}))
    _require(stage in expected, 'public_study_stage_unavailable')
    from .study_supervisor import check_live_study_resource
    check_live_study_resource(live_resource_ref, projection)
    if stage in {'inspect_windows', 'inspect_release', 'rank_encode', 'rank_score', 'rank_release'}:
        checkpoint = check_public_study_source_cuts(reference, source_cuts)
        if stage in {'inspect_release', 'rank_score', 'rank_release'}:
            reviews.check_reviewed_public_source_dataset(reference._a, source_cuts)
        _require(time.monotonic() < checkpoint.deadline, 'public_study_source_expired')
    else:
        _require(source_cuts == ())
    return projection


@contextmanager
def operation_public_source_cut(reference, *, batch):
    check_public_study_operation(reference)
    with reviews.reviewed_public_source_cut(reference._a, batch=batch) as result:
        yield result


def reviewed_public_study_inputs(reference):
    check_public_study_operation(reference)
    current = reviews.reviewed_public_dataset(reference._a)
    capture = reviews._Capture(reference._root)
    a_data = get_receipt(capture.root, capture.route['route_id'], reviews.KIND)['details']
    registration = _json(capture.read(a_data['registration_path']))
    raw = capture.read(registration['config']['path'], expected=registration['config'])
    _require(reviews.sha(raw) == current['facts']['config_sha256'])
    from .research_use_conditions import fixed_public_research_model_facts
    b_manifest = None
    if reference._b is not None:
        from .public_study_inspection import reviewed_public_inspection_manifest
        b_manifest = reviewed_public_inspection_manifest(reference._b, reference._a)
    capture.recheck()
    runtime = reference._request['runtime']
    registered = {key: runtime[key] for key in ('inference_image_id', 'inspection_image_id', 'base_image_digest', 'recipe_digest')}
    registered.update(worker_source_digest=digest(reference._projection.worker_files),
        software_manifest_digest=digest(reference._projection.software_files),
        profile_digest=reference._projection.resource_profile_sha256)
    return PublicStudyInputs(current['inputs'], _json(raw), fixed_public_research_model_facts(), b_manifest, registered,
        digest(current['facts']['dataset']), _condition_check(reference._conditions, _PRODUCTION)['artifact_manifest_sha256'])


@state.serialized_task
def _revoke_public_study_operation(root, reference, composition):
    projection = _check_public_study_operation(reference, composition)
    capture = reviews._Capture(root)
    _require(capture.root == projection.root)
    receipt = get_receipt(root, capture.route['route_id'], KINDS[projection.operation])
    details = {**receipt['details'], 'state': 'revoked'}
    write_receipt(root, KINDS[projection.operation], 'observed', details=details,
                  expected_context=capture.context, interrupt_check=capture.recheck)
    for snapshot in reference._exports:
        snapshot.close()
    return {'status': 'observed', 'state': 'revoked', 'ranking_permitted': False}


def revoke_public_study_operation(root, reference):
    """Current owner revokes the existing intent; this never rearms a holdout."""
    return _revoke_public_study_operation(root, reference, _PRODUCTION)


_FUNCTION_CATALOGS = (
    ('small', '61f5fb2065b9783ef2a372f1fdbcd65e1d5f61d5d7ccbf5e8b02d45d9fa4cb01', 62),
    ('large', '7074d347cd44df604a1dab7e5dc5928ba63862685be2b97f4f49d08f70fb8e14', 2194))


def reviewed_public_study_catalog(reference):
    """All fixed public files, including those without indexed functions; data only."""
    projection = check_public_study_operation(reference)
    capture = reviews._Capture(projection.root)
    from .research import _catalog
    with reviews.native_root(projection.root) as anchor:
        rows, _ = _catalog(anchor)
    capture.recheck()
    return tuple((path.split('/', 1)[0], path.split('/', 1)[1], commit, size, sha256)
                 for path, size, sha256, commit in rows)


def reviewed_public_study_functions(reference):
    """Return exact original eight-key rows; do not regenerate AST eligibility."""
    import json
    from .study_windows import FUNCTION_FIELDS
    projection = check_public_study_operation(reference)
    capture = reviews._Capture(projection.root)
    result = []
    for corpus, expected_sha256, expected_count in _FUNCTION_CATALOGS:
        path = 'engineering/benchmarks/issue162/data/' + corpus + '-functions.json'
        raw = capture.read(path, source=True, limit=1048576)
        _require(reviews.sha(raw) == expected_sha256, 'public_study_functions_changed')
        # These immutable source tables have a pinned list format, unlike the
        # unchanged four-candidate-file object schema. Their byte bound stays1MiB.
        rows = json.loads(raw)
        _require(type(rows) is list and len(rows) == expected_count
                 and all(type(row) is dict and set(row) == FUNCTION_FIELDS for row in rows))
        result.append((corpus, tuple(rows)))
    capture.recheck()
    return tuple(result)


def reviewed_public_study_graphs(reference):
    """Return actual retained inert graph data, not native execution authority."""
    projection = check_public_study_operation(reference)
    capture = reviews._Capture(projection.root)
    conditions = _condition_check(reference._conditions, _PRODUCTION)
    from .public_study_graphs import graph_observations
    result = graph_observations(capture, reference._request['graph_observations'], conditions['models'])
    capture.recheck()
    return result
