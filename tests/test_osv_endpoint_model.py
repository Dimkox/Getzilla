"""Bind each scanner destination to its declared data and failure contract."""
import json
import unittest
from tests._support import PROJECT


class OsvEndpointModelTests(unittest.TestCase):
    def test_each_scanner_flow_has_its_own_destination_and_contract(self):
        model = json.loads((PROJECT / 'architecture/system.yaml').read_text())
        edges = {edge['id']: edge for edge in model['edges']}
        nodes = {node['id']: node for node in model['nodes']}
        for identity, destination in (
            ('EDGE-SCANNER-OSV-QUERY', 'NODE-OSV-API'),
            ('EDGE-SCANNER-OSV-MIRROR-DOWNLOAD', 'NODE-OSV-ADVISORY-BUCKET'),
        ):
            with self.subTest(flow=identity):
                self.assertTrue(identity in edges, 'Missing scanner flow: ' + identity)
                edge = edges[identity]
                self.assertEqual(edge['from'], 'NODE-LOCAL-VULNERABILITY-SCANNER')
                self.assertEqual(edge['to'], destination)
                expected_data = ['DATA-VULNERABILITY-ADVISORY']
                if identity == 'EDGE-SCANNER-OSV-QUERY':
                    expected_data.insert(0, 'DATA-PACKAGE-IDENTITY')
                self.assertEqual(edge['allowed_data'], expected_data)
                self.assertEqual(edge['protocol'], 'https')
                self.assertEqual(edge['authentication'], 'none')
                self.assertEqual(edge['failure_behavior']['mode'], 'fail_closed')
                self.assertEqual(edge['failure_behavior']['terminal_action'], 'reject')
                self.assertEqual(edge['failure_behavior']['max_retries'], 0)
                self.assertEqual(nodes[destination]['type'], 'external_system')
                self.assertEqual(nodes[destination]['trust_domain'], 'TD-EXTERNAL-PLATFORM')
