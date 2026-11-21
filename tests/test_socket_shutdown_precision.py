"""Pure, closed AST controls for shutdown constants versus real TCP clients."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from getzilla import architecture_fitness as fitness
from tests.test_batch_composition_joins import pure


class SocketShutdownPrecisionTests(unittest.TestCase):
    def classify(self, source):
        tree = ast.parse(source)
        path = 'owned/http_response.py'
        snapshot = SimpleNamespace(system={
            'nodes': [{'id': 'owned-worker', 'type': 'worker', 'repository_paths': [path]}],
            'edges': [{'from': 'owned-worker', 'protocol': 'https'}]}, rules={'network_policies': [{
                'id': 'owned-declared-only', 'node_types': ['worker'],
                'allowed_protocols': ['https', 'tcp'], 'require_declared_edge': True}]})
        diff = SimpleNamespace(artifacts=[SimpleNamespace(path=path, status='added')])
        inventory = SimpleNamespace(root=Path('owned-inert'), tree=lambda _: tree)
        with mock.patch.object(fitness, '_project_import_roots', return_value=set()), pure():
            families = fitness._network_families(tree, set())
            result = fitness._network_clients(snapshot, diff, inventory)
        return families, result

    def test_only_shutdown_constants_need_no_invented_tcp_edge(self):
        for constant in ('SHUT_RD', 'SHUT_WR', 'SHUT_RDWR'):
            with self.subTest(constant=constant):
                families, result = self.classify('import socket\n'
                    'def interrupt(stream):\n    stream.shutdown(socket.' + constant + ')\n')
                self.assertNotIn('socket', families)
                self.assertEqual(result.status, 'not_applicable')

    def test_actual_bounded_response_module_keeps_https_without_raw_tcp(self):
        source = (Path(__file__).resolve().parents[1] /
                  'trust-ci/src/adaptive_trust_ci/http_response.py').read_text()
        families, result = self.classify(source)
        self.assertNotIn('socket', families)
        self.assertIn('urllib.request', families)
        self.assertEqual(result.status, 'pass')

    def test_unknown_or_real_socket_semantics_keep_the_original_tcp_refusal(self):
        cases = {
            'raw': 'socket.socket()',
            'connect': 'socket.create_connection(("fixture.invalid", 443))',
            'dynamic': 'getattr(socket, "SHUT_RDWR")',
            'escape': 'supplier = socket',
            'return': 'def escape():\n    return socket',
            'argument': 'consume(socket)',
            'rebinding': 'socket = replacement\nsocket.SHUT_RDWR',
            'parameter': 'def shutdown(socket):\n    return socket.SHUT_RDWR',
            'constant_call': 'socket.SHUT_RDWR()',
            'mutation': 'socket.SHUT_RDWR = replacement',
            'global': 'def mutate():\n    global socket\n    socket.SHUT_RDWR',
            'namespace': 'globals()["socket"]',
            'unknown_alias': 'alias = socket\nalias.SHUT_RDWR',
            'shadow_import': 'import replacement as socket\nsocket.SHUT_RDWR',
        }
        for name, use in cases.items():
            with self.subTest(case=name):
                families, result = self.classify('import socket\n' + use + '\n')
                self.assertIn('socket', families)
                self.assertEqual(result.status, 'fail')

    def test_unproven_import_aliases_and_from_imports_still_require_tcp(self):
        for source, family in [('import socket as client\nclient.SHUT_RDWR\n', 'socket'),
                               ('from socket import SHUT_RDWR\nconsume(SHUT_RDWR)\n', 'socket.SHUT_RDWR')]:
            with self.subTest(source=source):
                families, result = self.classify(source)
                self.assertIn(family, families)
                self.assertEqual(result.status, 'fail')
