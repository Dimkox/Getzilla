import unittest

from getzilla.retrieval.study_inspection_manifest import worker_contract


class ScientificManifestTests(unittest.TestCase):
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
