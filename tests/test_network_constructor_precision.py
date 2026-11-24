"""Owned AST data-only constructor proof; no network or project classifier."""
import ast
from pathlib import Path
import unittest

from getzilla import architecture_fitness as fitness
from tests.test_batch_composition_joins import pure


class ConstructorPrecisionTests(unittest.TestCase):
    def facts(self, source):
        tree = ast.parse(source)
        with pure():
            return fitness._non_client_imports(tree), fitness._network_families(tree, set())

    def test_request_and_http_error_direct_constructors_are_data_only(self):
        source = "import urllib.error\ndef owned():\n import urllib.request\n return urllib.request.Request('https://owned.invalid')\ndef error():\n return urllib.error.HTTPError('https://owned.invalid',403,'denied',{},None)\n"
        nonclients, families = self.facts(source)
        self.assertTrue({'urllib.request', 'urllib.error'} <= nonclients)
        self.assertEqual(families, set())

    def test_actual_http_limit_fixture_has_complete_constructor_only_bindings(self):
        source = (Path(__file__).resolve().parents[1]/'trust-ci/tests/test_http_response_limits.py').read_text()
        nonclients, families = self.facts(source)
        self.assertTrue({'urllib.request', 'urllib.error'} <= nonclients)
        self.assertFalse(any(name.startswith('urllib') for name in families))

    def test_completion_boundary_binds_only_owned_loopback_and_data_request(self):
        source = (Path(__file__).resolve().parents[1]/'trust-ci/tests/test_http_response_completion.py').read_text()
        tree = ast.parse(source)
        nonclients, families = self.facts(source)
        self.assertIn('urllib.request', nonclients)
        self.assertFalse(any(name.startswith('urllib') for name in families))
        servers = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                   and isinstance(n.func, ast.Name) and n.func.id == 'HTTPServer']
        self.assertEqual(len(servers), 1)
        self.assertEqual(ast.literal_eval(servers[0].args[0]), ('127.0.0.1', 0))
        self.assertIn("'http://127.0.0.1:'", source)
        self.assertIn('server.handle_request', source)
        self.assertIn('worker.join(3)', source)
        self.assertIn('server.timeout = 2', source)

    def test_clients_escape_rebinding_and_dynamic_instrumentation_still_require_network(self):
        variants = (
            "urllib.request.urlopen('https://owned.invalid')",
            "urllib.request.build_opener()",
            "factory=urllib.request.Request",
            "class Escape(urllib.request.Request): pass",
            "alias=urllib.request",
            "getattr(urllib.request,'Request')('https://owned.invalid')",
            "urllib.request.Request=lambda value: value",
            "urllib=object()",
            "from unittest import mock\nmock.patch('urllib.request.Request',object())",
            "from unittest import mock\ntarget='urllib.request.Request'\nmock.patch(target,object())",
            "from unittest import mock\nfactory=mock.patch\nfactory('urllib.request.Request',object())",
            "from unittest import mock\nmock.patch('unrelated.policy.interpreter',object())",
            "from unittest import mock\nfrom getzilla import architecture_fitness\nmock.patch('getzilla.architecture_fitness.namespace_is_closed',object())",
        )
        for body in variants:
            with self.subTest(body=body):
                nonclients, families = self.facts('import urllib.request\n'+body+'\n')
                self.assertNotIn('urllib.request', nonclients)
                self.assertTrue(any(name.startswith('urllib') for name in families))

    def test_constructor_import_alias_forms_remain_explicitly_unproved(self):
        for source in ("from urllib.request import Request\nRequest('https://owned.invalid')",
                       "import urllib.request as other\nother.Request('https://owned.invalid')"):
            with self.subTest(source=source):
                nonclients, families = self.facts(source)
                self.assertFalse(any(name.startswith('urllib') for name in nonclients))
                self.assertTrue(any(name.startswith('urllib') for name in families))
