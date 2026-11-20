"""Closed factual graph records confer no runtime permission."""
from copy import deepcopy
import unittest
from getzilla.retrieval import public_study_graphs as owner


class GraphObservationTests(unittest.TestCase):
    def records(self):
        models = tuple((name, {'graph': {'path': name + '/onnx/model.onnx', 'bytes': 1, 'sha256': 'a' * 64},
                              'external_files': ()}) for name in ('minilm', 'bge_m3'))
        metadata = {'schema_version': 1, 'schema': 'onnx-v1.19.1-wire-metadata', 'graph_bytes': 1,
            'graph_sha256': 'a' * 64, 'graph_sha256_verified': True, 'external_files': {},
            'external_hashes_verified': False, 'metadata_profile_supported': True, 'runtime_supported': False,
            'runtime_qualification': 'not_performed', 'unsupported_features': [],
            'inputs': [{'name': 'ids', 'dtype': 7, 'shape': ['batch', 'sequence']}],
            'outputs': [{'name': 'raw', 'dtype': 1, 'shape': ['batch', 'sequence', 384]}], 'opsets': [14]}
        documents = {'minilm': deepcopy(metadata), 'bge_m3': {'kind': 'operator_inert_bge_refined_closure_metadata',
            'status': 'metadata_observed', 'model_execution': False, 'runtime_admission': False,
            'independent_phase_b_review': False, 'metadata': deepcopy(metadata)}}
        class Capture:
            def json(self, reference):
                return documents[reference['name']]
        refs = {name: {'name': name, 'sha256': sha} for name, sha in owner.REPORT_SHA256.items()}
        return Capture(), refs, models, documents

    def test_factual_projection_retains_no_runtime_and_is_immutable(self):
        capture, refs, models, _ = self.records()
        observed = owner.graph_observations(capture, refs, models)
        self.assertIs(observed['minilm']['runtime_supported'], False)
        with self.assertRaises(TypeError):
            observed['minilm']['runtime_supported'] = True

    def test_changed_identity_qualification_and_graph_refuse(self):
        for field, value in (('runtime_supported', True), ('external_hashes_verified', True),
                             ('graph_sha256', 'b' * 64), ('unsupported_features', ['unknown'])):
            with self.subTest(field=field):
                capture, refs, models, documents = self.records()
                documents['minilm'][field] = value
                with self.assertRaises(ValueError):
                    owner.graph_observations(capture, refs, models)
        capture, refs, models, _ = self.records()
        refs['minilm']['sha256'] = 'b' * 64
        with self.assertRaises(ValueError):
            owner.graph_observations(capture, refs, models)
