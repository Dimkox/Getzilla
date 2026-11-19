from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla import ci_gate, verification
from getzilla.doctor import run_doctor
from tests.test_ci_gate import fake_runner, no_network
from tests.test_installer import MODULE as installer


@unittest.skipUnless(shutil.which('git'), 'Git required for trusted discovery')
class LanguageIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True, capture_output=True)
        (self.root / '.getzilla/config').mkdir(parents=True)

    def policy(self, mode='auto', enforcement='shadow'):
        section = {'mode': mode, 'enforcement': enforcement, 'sandbox': {'image': 'fixture@sha256:' + 'a' * 64},
                   'tools': {'eslint': {'launcher': ['/opt/eslint'], 'version': '9.0.0'}}}
        (self.root / '.getzilla/config/policy.json').write_text(json.dumps({'language_quality_gates': section}))

    def javascript(self):
        (self.root / 'app.js').write_text('const answer = 42;')
        (self.root / 'eslint.config.js').write_text('export default [];')

    def test_doctor_reports_nonapplicability_missing_config_and_unapproved_runner_without_execution(self):
        with patch('getzilla.doctor.check_toolchain', return_value=[]), \
             patch('getzilla.language_quality.sandbox.operator_images', return_value=frozenset()), \
             patch('getzilla.language_quality.sandbox.bounded_process', side_effect=AssertionError('doctor must not execute language tools')):
            (self.root / 'app.py').write_text('answer = 42')
            items = [item for item in run_doctor(self.root) if item.name.startswith('lqg:')]
            self.assertEqual(len(items), 7)
            self.assertTrue(all('NOT_APPLICABLE' in item.message for item in items))
            self.javascript()
            item = next(item for item in run_doctor(self.root) if item.name == 'lqg:eslint:.')
            self.assertIn('NOT_CONFIGURED', item.message)
            self.policy()
            item = next(item for item in run_doctor(self.root) if item.name == 'lqg:eslint:.')
            self.assertIn('UNSUPPORTED_RUNNER', item.message)
            self.assertEqual(item.status, 'info')
            (self.root / '.getzilla/config/policy.json').write_text('{')
            item = next(item for item in run_doctor(self.root) if item.name == 'lqg:policy:.')
            self.assertEqual(item.status, 'fail')

    def test_public_private_selection_and_workflow_bytes_ignore_optional_language_policy(self):
        signatures = {'public': set(), 'private': set()}
        for javascript, mode in ((False, 'auto'), (True, 'off'), (True, 'auto'), (True, 'on')):
            if javascript:
                self.javascript()
            else:
                (self.root / 'app.py').write_text('answer = 42')
            self.policy(mode)
            for visibility in ('public', 'private'):
                with self.subTest(javascript=javascript, mode=mode, visibility=visibility), \
                     patch.dict(os.environ, {'CI': 'true', 'TRUST_CI': '1', 'GITHUB_ACTIONS': 'true'}), \
                     patch('getzilla.language_quality.sandbox.operator_images', return_value=frozenset()), \
                     patch('getzilla.language_quality.sandbox.bounded_process', side_effect=AssertionError('environment is not operator admission')):
                    plan = ci_gate.plan_gate(self.root, ROOT, visibility=visibility, runner=fake_runner(), fetch=no_network)
                    self.assertEqual(plan['gate'], 'github-actions' if visibility == 'public' else 'trust-ci')
                    signatures[visibility].add(tuple((entry['path'], entry['sha256']) for entry in plan['writes']))
                    report, checks = verification._language_quality_report(self.root, None, None)
                    self.assertEqual(checks, [])
                    result = next(item for item in report['results'] if item['tool_id'] == 'eslint')
                    expected = 'NOT_APPLICABLE' if not javascript else 'SKIPPED_BY_POLICY' if mode == 'off' else 'UNSUPPORTED_RUNNER'
                    self.assertEqual(result['execution_status'], expected)
        self.assertEqual(len(signatures['public']), 1)
        self.assertEqual(signatures['private'], {()})
        self.policy('on', 'blocking')
        report, checks = verification._language_quality_report(self.root, None, None)
        self.assertTrue(checks)
        self.assertTrue(all(check.status == 'fail' for check in checks))

    def test_receipt_publication_failure_remains_fatal_with_cached_advisory(self):
        receipt = self.root / '.getzilla/runtime/receipts/fixture/verification.json'
        receipt.parent.mkdir(parents=True)
        receipt.write_text('{"status":"pass"}')
        report = {'status': 'pass', 'route_id': 'fixture', 'checks': [],
                  'advisory': {'lqg': {'results': [{'execution_status': 'CACHED_UNVERIFIED',
                                                 'cache_hit': True, 'enforcement': 'shadow'}]}}}
        with patch('getzilla.verification.write_receipt', side_effect=OSError('fixture publication failure')):
            verification._record_verification_receipt(self.root, report, 'a' * 64)
        self.assertEqual((report['status'], report['evidence_status']), ('fail', 'failed'))
        self.assertEqual(report['checks'][-1]['name'], 'receipt-recording')
        self.assertFalse(receipt.exists())
        self.assertEqual(report['advisory']['lqg']['results'][0]['execution_status'], 'CACHED_UNVERIFIED')


class ConsumerPayloadTests(unittest.TestCase):
    def test_language_docs_and_consumer_link_are_shipped_with_runtime(self):
        payload = {entry.path: entry.content for entry in installer.build_payload(ROOT)}
        self.assertTrue('.getzilla/getzilla/language_quality/core.py' in payload, 'LQG runtime missing')
        self.assertTrue('.getzilla/getzilla/language_quality/cache.py' in payload, 'LQG cache missing')
        self.assertTrue('docs/LANGUAGE_QUALITY_GATES.md' in payload, 'LQG consumer documentation missing')
        self.assertEqual(payload['docs/LANGUAGE_QUALITY_GATES.md'], (ROOT / 'docs/LANGUAGE_QUALITY_GATES.md').read_bytes())
        self.assertIn(b'](docs/LANGUAGE_QUALITY_GATES.md)', payload['AGENTS.md'])


if __name__ == '__main__':
    unittest.main()
