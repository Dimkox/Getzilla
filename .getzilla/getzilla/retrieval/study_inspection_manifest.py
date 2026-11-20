"""Assemble fixed INSPECT facts; returned dictionaries never confer Phase B."""
from collections import Counter

from .budget import RetrievalError
from .contracts import digest, hex_digest
from .study_plan import EXPECTED_WINDOWS, EXPECTED_FUNCTIONS, MODELS
from .study_codec import CODEC_SHA256, CODEC_BYTES


def assemble(inputs, projection, *, catalog, graphs, tokenizers, conformance,
             windows, lengths, packing, execution_id, readback_digest):
    if (not hex_digest(readback_digest) or set(graphs) != set(MODELS)
            or set(tokenizers) != set(MODELS) or set(conformance) != set(MODELS)
            or type(windows) not in {list, tuple}
            or Counter(row['corpus'] for row in windows) != Counter(EXPECTED_WINDOWS)):
        raise RetrievalError('study_scientific_inspection_incomplete')
    ordered = sorted(windows, key=lambda row: (('small', 'large').index(row['corpus']), row['id']))
    if len({(row['corpus'], row['id']) for row in ordered}) != 3884:
        raise RetrievalError('study_scientific_inspection_incomplete')
    pins = {path: (size, checksum) for path, size, checksum in projection.artifact_files}
    facts = {row['model_key']: row for row in inputs.model_facts}
    if set(facts) != set(MODELS):
        raise RetrievalError('study_scientific_inspection_incomplete')
    models, counts, all_lengths = {}, {}, []
    for model, width, pooling in (('minilm', 384, 'masked_mean'), ('bge_m3', 1024, 'first_cls')):
        graph, tokenizer, probe = graphs[model], tokenizers[model], conformance[model]
        if (probe.get('vector_dimension') != width or not hex_digest(probe.get('vector_digest'))
                or tokenizer['tokenizer_sha256'] != pins[model + '/tokenizer.json'][1]
                or graph['graph_sha256'] != pins[model + '/onnx/model.onnx'][1]):
            raise RetrievalError('study_scientific_inspection_incomplete')
        inputs_meta = graph['inputs']
        raw = [row for row in graph['outputs'] if row['dtype'] == 1
               and row['shape'] is not None and len(row['shape']) == 3 and row['shape'][-1] == width]
        if (len(raw) != 1 or not inputs_meta or any(row['dtype'] != 7 for row in inputs_meta)
                or any(tuple(row['shape']) != tuple(inputs_meta[0]['shape']) for row in inputs_meta)):
            raise RetrievalError('study_scientific_inspection_incomplete')
        selected = raw[0]
        additional = [row for row in graph['outputs'] if row['name'] != selected['name']]
        if any(row['dtype'] != 1 for row in additional):
            raise RetrievalError('study_scientific_inspection_incomplete')
        external = {} if model == 'minilm' else {'model.onnx_data': {
            'bytes': pins[model + '/onnx/model.onnx_data'][0],
            'sha256': pins[model + '/onnx/model.onnx_data'][1]}}
        models[model] = {'revision': facts[model]['revision'],
            'tokenizer_sha256': tokenizer['tokenizer_sha256'],
            'graph_sha256': graph['graph_sha256'], 'external_files': external,
            'graph_inspection_digest': graph['report_sha256'],
            'tokenizer_inspection_digest': digest(tokenizer), 'session_conformance_digest': digest(probe),
            'input_contract': {'names': [row['name'] for row in inputs_meta], 'dtype': 'int64',
                               'shape': list(inputs_meta[0]['shape'])},
            'output_contract': {'name': selected['name'], 'dtype': 'float32', 'shape': list(selected['shape']),
                'additional_outputs': [{'name': row['name'], 'dtype': 'float32', 'shape': list(row['shape'])}
                                       for row in additional]},
            'pooling': pooling, 'max_tokens': 256, 'batch': 1, 'precision': 'float32', 'l2_epsilon': 1e-12}
        count = 0
        for row in ordered:
            key = model, row['corpus'], row['id']
            value = ({'raw_tokens': row['encoder_tokens'], 'truncated': row['encoder_truncated']}
                     if model == 'minilm' else lengths.get(key))
            if (type(value) is not dict or type(value.get('raw_tokens')) is not int
                    or type(value.get('truncated')) is not bool):
                raise RetrievalError('study_scientific_inspection_incomplete')
            count += value['truncated']
            all_lengths.append((model, row['corpus'], row['id'], value['raw_tokens'], value['truncated']))
        counts[model] = count
    runtime = dict(inputs.runtime_registration)
    runtime.update(actual_readback_digest=readback_digest,
        native_execution_binding_digest=digest({'execution_id': execution_id,
            'image_id': projection.image_id, 'registration_sha256': projection.registration_sha256,
            'resource_readback_digest': readback_digest}))
    return {'schema_version': 1, 'definition': 'issue162-offline-inspection-v1',
        'registration_digest': projection.registration_sha256,
        'dataset_digest': inputs.dataset_digest, 'phase_a_binding_digest': projection.phase_a_sha256,
        'artifact_manifest_digest': inputs.artifact_manifest_digest,
        'window_manifest': {'definition': 'minilm-special-token-counted-254-overlap2-v1',
            'source_mapping_digest': digest({'files': catalog,
                'functions': [(universe['corpus'], row['function_id'], row['historical_id'],
                               row['path'], row['start'], row['end'], row['declaration_sha256'])
                    for universe in inputs.dataset[0]['universes'] for row in universe['functions']]}),
            'ordered_windows_digest': digest(ordered),
            'untruncated_lengths_digest': digest(all_lengths), 'corpus_windows': dict(EXPECTED_WINDOWS),
            'function_universes': dict(EXPECTED_FUNCTIONS), 'overlong_line_count': len({
                (row['corpus'], row['path'], row['start']) for row in ordered
                if row['start'] == row['end'] and row['encoder_tokens'] > 254}),
            'truncation_counts': counts},
        'models': models, 'codec': {'name': 'o200k_base', 'bytes': CODEC_BYTES, 'sha256': CODEC_SHA256,
            'citation_definition': 'issue162-complete-context-serialization-v1',
            'packing_parity_digest': digest(packing)}, 'runtime': runtime}


def worker_contract(graph, model):
    """Project actual inert signatures without guessing names or pooled widths."""
    width = {'minilm': 384, 'bge_m3': 1024}[model]
    outputs = [row for row in graph['outputs'] if row['dtype'] == 1 and row['shape'] is not None
               and len(row['shape']) == 3 and row['shape'][-1] == width]
    if len(outputs) != 1 or not graph['inputs']:
        raise RetrievalError('study_graph_signature_unavailable')
    output = outputs[0]
    return {'inputs': [row['name'] for row in graph['inputs']], 'output': output['name'],
        'input_shape': list(graph['inputs'][0]['shape']), 'output_shape': list(output['shape']),
        'additional_outputs': [(row['name'], 'tensor(float)', list(row['shape']))
            for row in graph['outputs'] if row['name'] != output['name']]}
