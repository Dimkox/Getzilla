"""Proven stdlib assertions compare data while nested paid calls stay visible."""
from __future__ import annotations

import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.cost_guard import python_findings


class AssertionCostBoundaryTests(unittest.TestCase):
    def findings(self, body):
        return python_findings('sample.py', textwrap.dedent(body).encode())

    def test_inherited_unittest_assertion_compares_endpoint_without_a_paid_call(self):
        for imported, base in (('import unittest', 'unittest.TestCase'),
                               ('from unittest import TestCase as Case', 'Case')):
            with self.subTest(base=base):
                source = imported + '\nclass PreviewTest(' + base + '):\n' + textwrap.indent(
                    'def test_endpoint(self):\n    self.assertEqual(preview.endpoint, "https://api.openai.com/v1/responses")\n', '    ')
                self.assertEqual(self.findings(source), [])

    def test_nested_provider_call_is_still_found_inside_a_proven_assertion(self):
        found = self.findings('''
            import unittest
            import requests
            class PreviewTest(unittest.TestCase):
                def test_endpoint(self):
                    self.assertEqual(requests.post("https://api.openai.com/v1/responses"),
                                     "https://api.openai.com/v1/responses")
        ''')
        self.assertEqual([(item.kind, item.detail) for item in found], [('PAID_CALL', 'requests.post')])

    def test_unproved_or_overridden_assertion_keeps_the_paid_host_signal(self):
        for declaration in ('class PreviewTest:',
                            'class PreviewTest(unittest.TestCase):\n    def assertEqual(self, *args): pass',
                            'class PreviewTest(unittest.TestCase):\n    def __getattribute__(self, name): pass',
                            'class PreviewTest(unittest.TestCase):\n    assertEqual = requests.post',
                            'class PreviewTest(unittest.TestCase):\n    assertEqual: object = requests.post',
                            'class PreviewTest(unittest.TestCase):\n    assertEqual, other = requests.post, None',
                            'class PreviewTest(unittest.TestCase):\n    from requests import post as assertEqual',
                            'class PreviewTest(unittest.TestCase):\n    assertEqual = staticmethod(requests.post)',
                            'class PreviewTest(unittest.TestCase):\n    assertEqual = classmethod(requests.post)'):
            source = 'import unittest\nimport requests\n' + declaration + '\n' + textwrap.indent(
                'def test_endpoint(self):\n    self.assertEqual(preview.endpoint, "https://api.openai.com/v1/responses")\n', '    ')
            with self.subTest(declaration=declaration):
                self.assertTrue(any(item.kind == 'PAID_CALL' and item.detail == 'self.assertEqual'
                                    for item in self.findings(source)))

    def test_dynamic_assertion_changes_and_nested_receiver_shadowing_stay_opaque(self):
        variants = (
            '''import unittest
import requests
class PreviewTest(unittest.TestCase):
    def test_endpoint(self):
        setattr(self, 'assertEqual', requests.post)
        self.assertEqual(preview.endpoint, "https://api.openai.com/v1/responses")
''',
            '''import unittest
class PreviewTest(unittest.TestCase):
    def test_endpoint(self):
        def invoke(self):
            self.assertEqual(preview.endpoint, "https://api.openai.com/v1/responses")
        invoke(client)
''',
            '''import unittest
from other import unittest
class PreviewTest(unittest.TestCase):
    def test_endpoint(self):
        self.assertEqual(preview.endpoint, "https://api.openai.com/v1/responses")
''',
            '''import unittest
import requests
setattr(unittest.TestCase, 'assertEqual', requests.post)
class PreviewTest(unittest.TestCase):
    def test_endpoint(self):
        self.assertEqual("https://api.openai.com/v1/responses")
''',
            '''import unittest
unittest.TestCase = ProviderClient
class PreviewTest(unittest.TestCase):
    def test_endpoint(self):
        self.assertEqual("https://api.openai.com/v1/responses")
''',
            '''import unittest
from unittest.mock import patch
import requests
with patch.object(unittest, 'TestCase', ProviderClient):
    class PreviewTest(unittest.TestCase):
        def test_endpoint(self):
            self.assertEqual("https://api.openai.com/v1/responses")
''',
        )
        for source in variants:
            with self.subTest(source=source):
                self.assertTrue(any(item.detail == 'self.assertEqual' for item in self.findings(source)))
