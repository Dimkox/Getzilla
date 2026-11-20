import unittest
from types import SimpleNamespace

from getzilla.retrieval.study_inspection_manifest import worker_contract, assemble


class ScientificManifestTests(unittest.TestCase):
    def test_pure_assembly_matches_consumer_and_telemetry_cannot_change_scientific_digest(self):
        """Declared inert facts only; this never issues an operation/result/B ref."""
        from tests.test_public_study_manifest import fixture
        from getzilla.retrieval.public_study_manifest import validate_inspection_manifest
        original, binding = fixture()
        h = 'a' * 64
        inputs = SimpleNamespace(model_facts=tuple({'model_key': name, 'revision': 'b' * 40}
            for name in ('minilm', 'bge_m3')), dataset_digest=h, artifact_manifest_digest=h,
            dataset=({'universes': []},), runtime_registration={key: value
                for key, value in original['runtime'].items()
                if key not in {'actual_readback_digest', 'native_execution_binding_digest'}})
        projection = SimpleNamespace(artifact_files=binding['model_files'], image_id='sha256:' + h,
                                     registration_sha256=h, phase_a_sha256=h)
        graphs, tokenizers, probes = {}, {}, {}
        for model, width in (('minilm', 384), ('bge_m3', 1024)):
            graphs[model] = {'graph_sha256': h, 'report_sha256': h,
                'inputs': [{'name': name, 'dtype': 7, 'shape': ('batch', 'seq')}
                           for name in ('input_ids', 'attention_mask')],
                'outputs': [{'name': 'raw', 'dtype': 1, 'shape': ('batch', 'seq', width)}]}
            tokenizers[model] = {'tokenizer_sha256': h, 'operation_measurements': {'wall_seconds': .1}}
            probes[model] = {'vector_dimension': width, 'vector_digest': h,
                             'operation_measurements': {'wall_seconds': .2}}
        windows = [{'corpus': corpus, 'id': f'w{i}', 'path': 'inert.py', 'start': 1, 'end': 1,
                    'encoder_tokens': 3, 'encoder_truncated': False}
                   for corpus, count in (('small', 64), ('large', 3820)) for i in range(count)]
        lengths = {('bge_m3', row['corpus'], row['id']): {'raw_tokens': 3, 'truncated': False}
                   for row in windows}
        packing = {'2048': {'tokens': 3}, '8192': {'tokens': 3},
                   'operation_measurements': {'wall_seconds': .3}}
        def build():
            return assemble(inputs, projection, catalog=(), graphs=graphs, tokenizers=tokenizers,
                conformance=probes, windows=windows, lengths=lengths, packing=packing,
                execution_id='inert-existing-fixture', readback_digest=h)
        result = build()
        binding['runtime_registration'] = result['runtime']
        self.assertFalse(validate_inspection_manifest(result, binding)['ranking_permitted'])
        tokenizers['minilm']['operation_measurements']['wall_seconds'] = 100.
        probes['bge_m3']['operation_measurements']['wall_seconds'] = 200.
        packing['operation_measurements']['wall_seconds'] = 300.
        self.assertEqual(build(), result)
        lengths.pop(next(iter(lengths)))
        with self.assertRaises(ValueError):
            build()

    def test_raw_output_selected_from_actual_signature_and_symbolic_pooled_width_retained(self):
        graph = {'inputs': [{'name': 'actual_ids', 'dtype': 7, 'shape': ('batch', 'sequence')}],
            'outputs': [{'name': 'actual_tokens', 'dtype': 1, 'shape': ('batch', 'sequence', 1024)},
                        {'name': 'pooled', 'dtype': 1, 'shape': ('batch', 'unknown_width')}]}
        contract = worker_contract(graph, 'bge_m3')
        self.assertEqual(contract['output'], 'actual_tokens')
        self.assertEqual(contract['additional_outputs'][0][2][-1], 'unknown_width')
        graph['outputs'] = graph['outputs'][1:]
        with self.assertRaises(ValueError):
            worker_contract(graph, 'bge_m3')
