"""Inert manifest facts; these fixtures never issue inspection or runtime refs."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.getzilla'))
from getzilla.retrieval import public_study_manifest as manifest_owner


def fixture():
    h = 'a' * 64
    models = {}
    files = []
    for model, width in (('minilm', 384), ('bge_m3', 1024)):
        files.extend([(model + '/onnx/model.onnx', 100, h), (model + '/tokenizer.json', 100, h)])
        external = {} if model == 'minilm' else {'model.onnx_data': {'bytes': 100, 'sha256': h}}
        if external:
            files.append((model + '/onnx/model.onnx_data', 100, h))
        models[model] = {'revision': 'b' * 40, 'tokenizer_sha256': h, 'graph_sha256': h,
            'external_files': external, 'graph_inspection_digest': h, 'tokenizer_inspection_digest': h,
            'session_conformance_digest': h, 'input_contract': {'names': ['input_ids', 'attention_mask'],
                'dtype': 'int64', 'shape': ['batch', 'seq']},
            'output_contract': {'name': 'raw', 'dtype': 'float32', 'shape': ['batch', 'seq', width], 'additional_outputs': []},
            'pooling': 'masked_mean' if model == 'minilm' else 'first_cls',
            'max_tokens': 256, 'batch': 1, 'precision': 'float32', 'l2_epsilon': 1e-12}
    runtime = {key: h for key in ('base_image_digest', 'recipe_digest', 'worker_source_digest',
        'software_manifest_digest', 'profile_digest', 'actual_readback_digest')}
    runtime.update(inference_image_id='sha256:' + h, inspection_image_id='sha256:' + h,
        native_execution_binding_digest=h)
    document = {'schema_version': 1, 'definition': 'issue162-offline-inspection-v1',
        'registration_digest': h, 'dataset_digest': h, 'phase_a_binding_digest': h,
        'artifact_manifest_digest': h, 'window_manifest': {'definition': 'minilm-special-token-counted-254-overlap2-v1',
            'source_mapping_digest': h, 'ordered_windows_digest': h, 'untruncated_lengths_digest': h,
            'corpus_windows': {'small': 64, 'large': 3820}, 'function_universes': {'small': 55, 'large': 2194},
            'overlong_line_count': 0, 'truncation_counts': {'minilm': 0, 'bge_m3': 0}},
        'models': models, 'codec': {'name': 'o200k_base', 'bytes': 3613922,
            'sha256': '446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d',
            'citation_definition': 'issue162-complete-context-serialization-v1', 'packing_parity_digest': h},
        'runtime': runtime}
    report = {'schema_version': 1, 'kind': 'independent_public_study_inspection_review_v1',
        'reviewer': {'agent_task': 'independent-inspector', 'native_session_id': 'independent-session',
            'native_generation': None, 'role': 'data_reviewer'}, 'manifest_sha256': h,
        'coverage': ['tokenizers', 'windows', 'graphs', 'runtime', 'codec', 'resources'],
        'decision': 'supported', 'findings': [], 'rationale': 'Separate inert full-scope fixture.', 'limitations': []}
    binding = {'manifest_sha256': h, 'registration_sha256': h, 'dataset_sha256': h,
        'phase_a_sha256': h, 'artifact_manifest_sha256': h, 'resource_profile_sha256': h,
        'model_files': tuple(files), 'model_revisions': {'minilm': 'b' * 40, 'bge_m3': 'b' * 40},
        'graph_observation_sha256': {'minilm': h, 'bge_m3': h},
        'runtime_registration': deepcopy(runtime), 'independent_reviews': [report], 'author': ('author', 'author-session')}
    return document, binding


class PublicStudyManifestTests(unittest.TestCase):
    def test_complete_inert_manifest_is_data_not_permission(self):
        facts = manifest_owner.validate_inspection_manifest(*fixture())
        self.assertEqual(facts['windows'], 3884)
        self.assertFalse(facts['ranking_permitted'])

    def test_pooled_shape_bad_pins_limits_partial_review_and_self_review_refuse(self):
        for change in ('pooled', 'graph', 'window', 'batch', 'codec', 'runtime', 'source_report', 'partial', 'self'):
            with self.subTest(change=change):
                data, binding = fixture()
                if change == 'pooled':
                    data['models']['bge_m3']['output_contract']['shape'] = ['batch', 1024]
                elif change == 'graph':
                    data['models']['minilm']['graph_sha256'] = 'c' * 64
                elif change == 'window':
                    data['window_manifest']['corpus_windows']['large'] -= 1
                elif change == 'batch':
                    data['models']['bge_m3']['batch'] = True
                elif change == 'codec':
                    data['codec']['sha256'] = 'c' * 64
                elif change == 'runtime':
                    data['runtime']['actual_readback_digest'] = 'c' * 64
                elif change == 'source_report':
                    binding['independent_reviews'][0]['kind'] = 'independent_partial_qrels_v1'
                elif change == 'partial':
                    binding['independent_reviews'][0]['coverage'].remove('graphs')
                else:
                    binding['independent_reviews'][0]['reviewer']['native_session_id'] = 'author-session'
                with self.assertRaises(ValueError):
                    manifest_owner.validate_inspection_manifest(data, binding)
