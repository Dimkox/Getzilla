"""Current-owner publication of genuinely owned, independently reviewed inspection.

A source report, diagnostic status or imported JSON never issues this reference.
Native delivery comes only from the fixed supervisor's actual result owner.
"""
from pathlib import Path
import math
import time
from .. import state
from ..receipts import get_receipt, write_receipt
from ..execution_store import load_registry
from .contracts import digest, sha, hex_digest
from .evaluation_inputs_io import _json
from .public_review_inputs import _require, ScientificBudget
from .public_study_manifest import validate_inspection_manifest
from . import public_review_witness as reviews

KIND = 'retrieval-public-witness-b'
OUTCOME_KIND = 'retrieval-public-inspection-outcome'
_ISSUER = object()


class OperatorWitnessedPublicInspection:
    __slots__ = ('_issuer', '_root', '_receipt_sha256', '_a', '_operation', '_result')

    def __new__(cls, *args, **kwargs):
        raise TypeError('actual independently reviewed owned inspection required')

    def __setattr__(self, name, value):
        raise AttributeError('public inspection is immutable')

    def __reduce__(self):
        raise TypeError('public inspection cannot be serialized')


def _native(operation, result):
    from .public_study_operation import check_public_study_operation, INSPECT
    projection = check_public_study_operation(operation)
    _require(projection.operation == INSPECT, 'public_inspection_operation_required')
    from .study_supervisor import check_study_inspection_result
    observed = check_study_inspection_result(result, operation)
    _require(type(observed.report_bytes) is bytes and 0 < len(observed.report_bytes) <= 65536
             and type(observed.report_size) is int and observed.report_size == len(observed.report_bytes)
             and sha(observed.report_bytes) == observed.report_sha256
             and observed.registration_sha256 == projection.registration_sha256
             and (observed.image_id is None or observed.image_id == projection.image_id),
             'public_inspection_native_result_unavailable')
    return projection, observed


def _original_deadline(observed):
    deadline = getattr(observed, 'original_deadline', None)
    _require(type(deadline) is float and math.isfinite(deadline) and time.monotonic() < deadline,
             'public_inspection_original_deadline')
    return deadline


def _completed(observed):
    _original_deadline(observed)
    _require(observed.execution_status == 'succeeded' and observed.cleanup_status == 'confirmed'
             and observed.native_execution_observation == 'native-completed'
             and observed.image_id is not None and hex_digest(observed.resource_readback_digest),
             'public_inspection_observed_unavailable')


def _binding(root, operation, projection, observed, phase_a, independent):
    from .public_study_operation import _condition_check, _PRODUCTION, reviewed_public_study_graphs
    conditions = _condition_check(operation._conditions, _PRODUCTION)
    runtime = operation._request['runtime']
    expected_runtime = {key: runtime[key] for key in ('inference_image_id', 'inspection_image_id',
                                                    'base_image_digest', 'recipe_digest')}
    expected_runtime.update(worker_source_digest=digest(projection.worker_files),
        software_manifest_digest=digest(projection.software_files), profile_digest=projection.resource_profile_sha256,
        actual_readback_digest=observed.resource_readback_digest,
        native_execution_binding_digest=digest({'execution_id': observed.execution_id,
            'image_id': observed.image_id, 'registration_sha256': observed.registration_sha256,
            'resource_readback_digest': observed.resource_readback_digest}))
    record = load_registry(root)['records'][observed.execution_id]
    _require(record['operation_id'] == projection.operation_digest, 'public_inspection_native_result_unavailable')
    owner = record['owner']
    return {'manifest_sha256': observed.report_sha256, 'registration_sha256': projection.registration_sha256,
        'dataset_sha256': digest(phase_a['dataset']), 'phase_a_sha256': phase_a['witness_sha256'],
        'artifact_manifest_sha256': conditions['artifact_manifest_sha256'],
        'resource_profile_sha256': projection.resource_profile_sha256, 'model_files': conditions['artifact_files'],
        'model_revisions': {name: row['revision'] for name, row in conditions['models']},
        'runtime_registration': expected_runtime, 'independent_reviews': independent,
        'graph_observation_sha256': {name: row['report_sha256'] for name, row in reviewed_public_study_graphs(operation).items()},
        'author': (owner['agent_id'] or owner['session_id'], owner['session_id'])}


def _publications(capture, publications):
    _require(type(publications) is list and 1 <= len(publications) <= 16)
    reports = []
    for publication in publications:
        capture.check()
        _require(type(publication) is dict and set(publication) == {'annotation', 'reports', 'delivery', 'delivery_assurance'}
                 and publication['delivery_assurance'] in reviews.DELIVERY_ASSURANCES)
        capture.group_start = capture.used
        reports.append(capture.json(publication['annotation']))
        _require(type(publication['reports']) is list and 1 <= len(publication['reports']) <= 4)
        for reference in [*publication['reports'], publication['delivery']]:
            capture.read(reference['path'], limit=1048576, expected=reference, keep=False)
        capture.group_start = None
    return reports


@state.serialized_task
def _witness_public_inspection(root, registration_path, phase_a, operation, native_result):
    """Explicit owner observation; native result + independent six-scope facts required."""
    a_facts = reviews.consume_public_reviews(phase_a)
    projection, observed = _native(operation, native_result)
    _completed(observed)
    capture = reviews._Capture(root)
    _require(capture.root == projection.root and phase_a._root == str(capture.root)
             and projection.phase_a_sha256 == phase_a._receipt_digest)
    registration = _json(capture.read(registration_path))
    _require(type(registration) is dict and set(registration) == {'schema_version', 'kind', 'manifest', 'reviews'}
             and type(registration['schema_version']) is int and registration['schema_version'] == 1
             and registration['kind'] == 'operator-public-inspection/v1')
    raw = capture.read(registration['manifest']['path'], expected=registration['manifest'])
    _require(raw == observed.report_bytes, 'public_inspection_report_changed')
    original = capture.read(observed.report_relative_path, expected={'path': observed.report_relative_path,
        'sha256': observed.report_sha256, 'bytes': observed.report_size})
    _require(original == raw, 'public_inspection_report_changed')
    reports = _publications(capture, registration['reviews'])
    budget = ScientificBudget(capture.deadline)
    facts = validate_inspection_manifest(_json(raw), _binding(root, operation, projection, observed, a_facts, reports), budget=budget)
    def recheck():
        capture.recheck()
        _completed(_native(operation, native_result)[1])
    recheck()
    details = {'assurance': reviews.ASSURANCE, 'profile': reviews._PRODUCTION.profile,
        'statement': 'AUTOMATED COORDINATOR directly observed the listed independent inspection deliveries; no human or security approval.',
        'context': capture.context, 'physical_root': list(capture.physical_root), 'source_binding': list(capture.source_binding),
        'policy_sha256': capture.policy, 'module_manifest_sha256': capture.manifest,
        'phase_a_sha256': phase_a._receipt_digest, 'operation_digest': projection.operation_digest,
        'conditions_sha256': projection.conditions_sha256, 'manifest_sha256': observed.report_sha256,
        'native_execution_id': observed.execution_id, 'original_deadline': _original_deadline(observed),
        'resource_readback_digest': observed.resource_readback_digest,
        'facts': facts, 'publications': registration['reviews'],
        'dependencies': list(capture.dependencies.values())}
    previous = get_receipt(root, capture.route['route_id'], KIND)
    if previous is not None and previous['details']['context'] == capture.context:
        _require(previous['details'] == details, 'public_inspection_conflict')
        receipt = previous
    else:
        write_receipt(root, KIND, 'observed', details=details, expected_context=capture.context,
                      interrupt_check=recheck)
        receipt = get_receipt(root, capture.route['route_id'], KIND)
    _require(receipt is not None and receipt['details'] == details)
    recheck()
    result = object.__new__(OperatorWitnessedPublicInspection)
    for key, value in (('_issuer', _ISSUER), ('_root', str(capture.root)), ('_receipt_sha256', digest(receipt)),
        ('_a', phase_a), ('_operation', operation), ('_result', native_result)):
        object.__setattr__(result, key, value)
    consume_public_inspection(result, phase_a)
    return result


def _current(reference, phase_a):
    _require(type(reference) is OperatorWitnessedPublicInspection
             and getattr(reference, '_issuer', None) is _ISSUER
             and type(phase_a) is reviews.OperatorWitnessedPublicReviewedInputs
             and getattr(phase_a, '_issuer', None) is reviews._ISSUER
             and phase_a._profile == reviews._PRODUCTION.profile and phase_a._root == reference._root
             and reference._a._receipt_digest == phase_a._receipt_digest, 'public_inspection_unavailable')
    capture = reviews._Capture(reference._root)
    receipt = get_receipt(capture.root, capture.route['route_id'], KIND)
    _require(receipt is not None and digest(receipt) == reference._receipt_sha256)
    data = receipt['details']
    _require(data['assurance'] == reviews.ASSURANCE and data['profile'] == reviews._PRODUCTION.profile
             and data['context'] == capture.context and data['physical_root'] == list(capture.physical_root)
             and data['source_binding'] == list(capture.source_binding)
             and data['policy_sha256'] == capture.policy and data['module_manifest_sha256'] == capture.manifest)
    projection, observed = _native(reference._operation, reference._result)
    _completed(observed)
    _require(observed.report_sha256 == data['manifest_sha256'] and projection.phase_a_sha256 == phase_a._receipt_digest
             and observed.resource_readback_digest == data['resource_readback_digest']
             and _original_deadline(observed) == data['original_deadline'])
    capture.dependencies = {row['path']: row for row in data['dependencies']}
    capture.recheck()
    _completed(observed)
    return capture, receipt, observed


def consume_public_inspection(reference, phase_a):
    _, receipt, _ = _current(reference, phase_a)
    return {'assurance': reviews.ASSURANCE, 'witness_sha256': reference._receipt_sha256,
            'manifest_sha256': receipt['details']['manifest_sha256'], 'facts': receipt['details']['facts'],
            'ranking_permitted': False}


def public_inspection_deadline(reference, phase_a):
    """Original live execution clock, rederived from the genuine result owner."""
    _, _, observed = _current(reference, phase_a)
    return _original_deadline(observed)


def reviewed_public_inspection_manifest(reference, phase_a):
    _, _, observed = _current(reference, phase_a)
    return _json(observed.report_bytes)


@state.serialized_task
def _record_public_inspection_outcome(root, operation, native_result):
    """A genuine observed failure is retained; it never mints positive B."""
    projection, observed = _native(operation, native_result)
    _require(observed.execution_status != 'succeeded' or observed.cleanup_status != 'confirmed'
             or observed.native_execution_observation != 'native-completed')
    capture = reviews._Capture(root)
    _require(capture.root == projection.root)
    capture.read(observed.report_relative_path, expected={'path': observed.report_relative_path,
        'sha256': observed.report_sha256, 'bytes': observed.report_size})
    details = {'assurance': reviews.ASSURANCE, 'outcome': 'observed-unavailable', 'experiment': 'INCONCLUSIVE',
        'operation_digest': projection.operation_digest, 'native_execution_id': observed.execution_id,
        'report_sha256': observed.report_sha256, 'execution_status': observed.execution_status,
        'cleanup_status': observed.cleanup_status, 'native_execution_observation': observed.native_execution_observation,
        'resource_readback_digest': observed.resource_readback_digest, 'observed_image_id': observed.image_id,
        'expected_image_id': projection.image_id, 'context': capture.context,
        'source_binding': list(capture.source_binding), 'ranking_permitted': False}
    capture.recheck()
    write_receipt(root, OUTCOME_KIND, 'observed', details=details, expected_context=capture.context,
                  interrupt_check=capture.recheck)
    return {'status': 'observed-unavailable', 'experiment': 'INCONCLUSIVE', 'ranking_permitted': False}


def witness_public_inspection(root, registration_path, phase_a, operation, native_result):
    _require(type(phase_a) is reviews.OperatorWitnessedPublicReviewedInputs
             and getattr(phase_a, '_issuer', None) is reviews._ISSUER
             and phase_a._profile == reviews._PRODUCTION.profile and Path(phase_a._root) == Path(root),
             'public_inspection_unavailable')
    from .public_study_operation import check_public_study_operation
    _require(check_public_study_operation(operation).root == Path(root), 'public_inspection_unavailable')
    return _witness_public_inspection(root, registration_path, phase_a, operation, native_result)


def record_public_inspection_outcome(root, operation, native_result):
    from .public_study_operation import check_public_study_operation
    _require(check_public_study_operation(operation).root == Path(root), 'public_inspection_unavailable')
    return _record_public_inspection_outcome(root, operation, native_result)
