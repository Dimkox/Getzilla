"""Closed public-study inspection facts. A valid object grants no authority.

The witness owner must supply bindings from actual owned inspection output,
current protected registration and independently observed review publications.
This leaf never imports optional tokenizers/tensors or starts a process.
"""
from .contracts import hex_digest, label
from .budget import RetrievalError
from .public_review_inputs import ScientificBudget, _require, _reason, _reviewer
from .study_onnx_worker import ModelContract

COVERAGE = frozenset({'tokenizers', 'windows', 'graphs', 'runtime', 'codec', 'resources'})
CODEC_SHA256 = '446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d'


def _keys(value, names):
    _require(type(value) is dict and set(value) == set(names), 'public_inspection_incomplete')


def _integer(value, minimum, maximum):
    _require(type(value) is int and minimum <= value <= maximum, 'public_inspection_incomplete')


def _validate_inspection_manifest(document, binding, *, budget=None):
    """Check enumerated facts only; no dict, reviewer label or boolean mints B."""
    budget = ScientificBudget() if budget is None else budget
    _require(type(budget) is ScientificBudget)
    budget.check()
    _keys(document, ('schema_version', 'definition', 'registration_digest', 'dataset_digest',
        'phase_a_binding_digest', 'artifact_manifest_digest', 'window_manifest', 'models', 'codec', 'runtime'))
    _require(type(document['schema_version']) is int and document['schema_version'] == 1
             and document['definition'] == 'issue162-offline-inspection-v1')
    _keys(binding, ('manifest_sha256', 'registration_sha256', 'dataset_sha256', 'phase_a_sha256',
        'artifact_manifest_sha256', 'resource_profile_sha256', 'model_files', 'model_revisions',
        'runtime_registration', 'independent_reviews', 'author'))
    for field, expected in (('registration_digest', 'registration_sha256'), ('dataset_digest', 'dataset_sha256'),
            ('phase_a_binding_digest', 'phase_a_sha256'), ('artifact_manifest_digest', 'artifact_manifest_sha256')):
        _require(hex_digest(binding[expected]) and document[field] == binding[expected])
    _require(hex_digest(binding['manifest_sha256']) and hex_digest(binding['resource_profile_sha256']))
    _windows(document['window_manifest'])
    _codec(document['codec'])
    _models(document['models'], binding, budget)
    _runtime(document['runtime'], binding)
    reviewers = _reviews(binding, budget)
    budget.check()
    return {'qualification': 'public-inspection-consistency-only', 'windows': 3884,
            'models': ['minilm', 'bge_m3'], 'independent_reviewers': len(reviewers), 'ranking_permitted': False}


def _windows(window):
    _keys(window, ('definition', 'source_mapping_digest', 'ordered_windows_digest',
        'untruncated_lengths_digest', 'corpus_windows', 'function_universes', 'overlong_line_count', 'truncation_counts'))
    _require(window['definition'] == 'minilm-special-token-counted-254-overlap2-v1'
             and window['corpus_windows'] == {'small': 64, 'large': 3820}
             and window['function_universes'] == {'small': 55, 'large': 2194})
    for key in ('source_mapping_digest', 'ordered_windows_digest', 'untruncated_lengths_digest'):
        _require(hex_digest(window[key]))
    _integer(window['overlong_line_count'], 0, 4000000)
    _keys(window['truncation_counts'], ('minilm', 'bge_m3'))
    for count in window['truncation_counts'].values():
        _integer(count, 0, 3884)


def _codec(codec):
    _keys(codec, ('name', 'bytes', 'sha256', 'citation_definition', 'packing_parity_digest'))
    _require(codec['name'] == 'o200k_base' and type(codec['bytes']) is int and codec['bytes'] == 3613922
             and codec['sha256'] == CODEC_SHA256
             and codec['citation_definition'] == 'issue162-complete-context-serialization-v1'
             and hex_digest(codec['packing_parity_digest']))


def _models(models, binding, budget):
    _keys(models, ('minilm', 'bge_m3'))
    _keys(binding['model_revisions'], ('minilm', 'bge_m3'))
    pins = {}
    _require(type(binding['model_files']) is tuple and 1 <= len(binding['model_files']) <= 4000)
    for row in binding['model_files']:
        budget.check()
        _require(type(row) is tuple and len(row) == 3 and type(row[0]) is str and row[0] not in pins
                 and type(row[1]) is int and row[1] > 0 and hex_digest(row[2]))
        pins[row[0]] = row[1:]
    for name, width, pooling in (('minilm', 384, 'masked_mean'), ('bge_m3', 1024, 'first_cls')):
        budget.check()
        model = models[name]
        _keys(model, ('revision', 'tokenizer_sha256', 'graph_sha256', 'external_files', 'graph_inspection_digest',
            'tokenizer_inspection_digest', 'session_conformance_digest', 'input_contract', 'output_contract',
            'pooling', 'max_tokens', 'batch', 'precision', 'l2_epsilon'))
        _require(type(model['revision']) is str and model['revision'] == binding['model_revisions'][name]
                 and len(model['revision']) == 40 and all(c in '0123456789abcdef' for c in model['revision'])
                 and model['tokenizer_sha256'] == pins[name + '/tokenizer.json'][1]
                 and model['graph_sha256'] == pins[name + '/onnx/model.onnx'][1])
        expected_external = {} if name == 'minilm' else {'model.onnx_data': {
            'bytes': pins[name + '/onnx/model.onnx_data'][0], 'sha256': pins[name + '/onnx/model.onnx_data'][1]}}
        _require(model['external_files'] == expected_external)
        for key in ('graph_inspection_digest', 'tokenizer_inspection_digest', 'session_conformance_digest'):
            _require(hex_digest(model[key]))
        _require(type(model['batch']) is int and model['batch'] == 1
                 and type(model['max_tokens']) is int and model['max_tokens'] == 256
                 and model['pooling'] == pooling and model['precision'] == 'float32'
                 and type(model['l2_epsilon']) is float and model['l2_epsilon'] == 1e-12)
        inputs, output = model['input_contract'], model['output_contract']
        _keys(inputs, ('names', 'dtype', 'shape'))
        _keys(output, ('name', 'dtype', 'shape', 'additional_outputs'))
        _require(inputs['dtype'] == 'int64' and output['dtype'] == 'float32'
                 and type(inputs['names']) is list and type(inputs['shape']) is list
                 and type(output['shape']) is list and type(output['additional_outputs']) is list
                 and len(output['additional_outputs']) <= 1)
        additional = []
        for row in output['additional_outputs']:
            _keys(row, ('name', 'dtype', 'shape'))
            _require(row['dtype'] == 'float32' and type(row['shape']) is list)
            additional.append((row['name'], 'tensor(float)', tuple(row['shape'])))
        contract = ModelContract(name, tuple(inputs['names']), output['name'], tuple(inputs['shape']),
                                 tuple(output['shape']), tuple(additional))
        _require(contract.output_shape[-1] == width)


def _runtime(runtime, binding):
    _keys(runtime, ('inference_image_id', 'inspection_image_id', 'base_image_digest', 'recipe_digest',
        'worker_source_digest', 'software_manifest_digest', 'profile_digest', 'actual_readback_digest',
        'native_execution_binding_digest'))
    _require(runtime == binding['runtime_registration'] and runtime['profile_digest'] == binding['resource_profile_sha256'])
    for key, value in runtime.items():
        if key in ('inference_image_id', 'inspection_image_id'):
            _require(type(value) is str and value.startswith('sha256:') and hex_digest(value[7:]))
        else:
            _require(hex_digest(value))


def _reviews(binding, budget):
    reviews, author = binding['independent_reviews'], binding['author']
    _require(type(reviews) is list and 1 <= len(reviews) <= 16 and type(author) is tuple
             and len(author) == 2 and all(label(value) for value in author))
    covered, reviewers = set(), set()
    for report in reviews:
        budget.check()
        _keys(report, ('schema_version', 'kind', 'reviewer', 'manifest_sha256', 'coverage',
            'decision', 'findings', 'rationale', 'limitations'))
        _require(type(report['schema_version']) is int and report['schema_version'] == 1
                 and report['kind'] == 'independent_public_study_inspection_review_v1'
                 and report['manifest_sha256'] == binding['manifest_sha256']
                 and report['decision'] == 'supported' and report['findings'] == []
                 and _reason(report['rationale']) and type(report['limitations']) is list
                 and all(_reason(value) for value in report['limitations']))
        reviewer = _reviewer(report)
        _require(all(reviewer[index] != author[index] for index in (0, 1)), 'public_inspection_self_review')
        _require(type(report['coverage']) is list and 1 <= len(report['coverage']) <= len(COVERAGE)
                 and all(type(value) is str for value in report['coverage'])
                 and len(set(report['coverage'])) == len(report['coverage'])
                 and set(report['coverage']) <= COVERAGE)
        covered.update(report['coverage'])
        reviewers.add(reviewer)
    _require(covered == COVERAGE, 'public_inspection_review_incomplete')
    return reviewers


def validate_inspection_manifest(document, binding, *, budget=None):
    """Bounded factual consistency only; the canonical owner alone can issue B."""
    try:
        return _validate_inspection_manifest(document, binding, budget=budget)
    except RetrievalError:
        raise
    except (KeyError, TypeError, ValueError, IndexError, RecursionError):
        raise RetrievalError('public_inspection_incomplete') from None
