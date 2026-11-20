"""Exact retained inert graph observations. Data only, never runtime or PhaseB.

These two actual reports retain original no-runtime qualifiers. They cannot be
replaced with expected model-family strings or caller-authored metadata.
"""
from pathlib import PurePosixPath
from types import MappingProxyType

from .public_review_inputs import _require

REPORT_SHA256 = MappingProxyType({
    'minilm': '208dc8e1da7c20be19abf449202c32f48255a0a7202db4bcc8a7109ba5cbb901',
    'bge_m3': '92c7d3f2392a91bcd6c8a854f531cbed736be2ff2d2fc6b5be93ecada874aa44'})


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def graph_observations(capture, references, models):
    _require(type(references) is dict and set(references) == set(REPORT_SHA256),
             'public_study_graph_observation_required')
    model_map = dict(models)
    _require(set(model_map) == set(REPORT_SHA256))
    observed = {}
    for name, expected_sha in REPORT_SHA256.items():
        reference = references[name]
        _require(reference['sha256'] == expected_sha, 'public_study_graph_observation_changed')
        document = capture.json(reference)
        if name == 'bge_m3':
            _require(document['kind'] == 'operator_inert_bge_refined_closure_metadata'
                     and document['status'] == 'metadata_observed' and document['model_execution'] is False
                     and document['runtime_admission'] is False and document['independent_phase_b_review'] is False)
            metadata = document['metadata']
        else:
            metadata = document
        model, graph = model_map[name], model_map[name]['graph']
        parent = PurePosixPath(graph['path']).parent
        external = {PurePosixPath(row['path']).relative_to(parent).as_posix():
            {'bytes': row['bytes'], 'sha256': row['sha256']} for row in model['external_files']}
        _require(metadata['schema_version'] == 1 and metadata['schema'] == 'onnx-v1.19.1-wire-metadata'
                 and metadata['graph_bytes'] == graph['bytes'] and metadata['graph_sha256'] == graph['sha256']
                 and metadata['graph_sha256_verified'] is True and metadata['external_files'] == external
                 and metadata['external_hashes_verified'] is False and metadata['metadata_profile_supported'] is True
                 and metadata['runtime_supported'] is False and metadata['runtime_qualification'] == 'not_performed'
                 and metadata['unsupported_features'] == [], 'public_study_graph_observation_changed')
        observed[name] = _freeze({key: metadata[key] for key in ('inputs', 'outputs', 'opsets', 'graph_sha256',
            'graph_bytes', 'external_files', 'metadata_profile_supported', 'runtime_supported',
            'runtime_qualification', 'external_hashes_verified', 'unsupported_features')})
        observed[name] = MappingProxyType({**observed[name], 'report_sha256': expected_sha})
    return MappingProxyType(observed)
