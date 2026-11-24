"""Exact retained terms and ancillary files grant distinct kinds of evidence."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_license_texts as texts

FULL = json.loads((ROOT / 'tests/fixtures/security-license-frontier-variants.json').read_text(encoding='utf-8'))
ANCILLARY = json.loads((ROOT / 'tests/fixtures/security-license-frontier-ancillary.json').read_text(encoding='utf-8'))
REFERENCES = json.loads((ROOT / 'tests/fixtures/security-license-frontier-references.json').read_text(encoding='utf-8'))


class FrontierLicenseTextTests(unittest.TestCase):
    def ancillary(self, text):
        self.assertTrue(callable(getattr(texts, 'reviewed_ancillary', None)), 'missing closed ancillary boundary')
        return texts.reviewed_ancillary(text)

    def test_complete_reviewed_terms_match_existing_identifiers(self):
        for item in FULL:
            with self.subTest(package=item['package'], member=item['member']):
                self.assertEqual(hashlib.sha256(item['text'].encode('utf-8')).hexdigest(), item['sha256'])
                self.assertEqual(texts.recognized_license(item['text']), item['identifier'])
                self.assertIsNone(self.ancillary(item['text']))

    def test_restricted_truncated_and_changed_complete_terms_refuse(self):
        for item in FULL:
            text = item['text']
            self.assertIn('"AS IS"', text)
            for changed in (text + '\nRedistribution is prohibited.\n', text[:len(text) // 2],
                            text.replace('"AS IS"', '"AS AVAILABLE"')):
                with self.subTest(package=item['package'], changed=changed[-60:]):
                    self.assertIsNone(texts.recognized_license(changed))

    def test_exact_ancillary_preserves_closed_reference_requirements_without_term_credit(self):
        for item in ANCILLARY:
            with self.subTest(package=item['package']):
                self.assertEqual(hashlib.sha256(item['text'].encode('utf-8')).hexdigest(), item['sha256'])
                self.assertEqual(self.ancillary(item['text']), item['expected'])
                self.assertIsNone(texts.recognized_license(item['text']))

    def test_ancillary_result_cannot_change_future_reference_requirements(self):
        for item in ANCILLARY:
            result = self.ancillary(item['text'])
            result['kind'] = 'full-license'
            result['required_files'].clear()
            with self.subTest(package=item['package']):
                self.assertEqual(self.ancillary(item['text']), item['expected'])

    def test_every_required_reference_retains_its_exact_complete_terms(self):
        sources = {item['sha256']: item for item in FULL + REFERENCES}
        for item in ANCILLARY:
            for name, digest in self.ancillary(item['text'])['required_files'].items():
                with self.subTest(package=item['package'], reference=name):
                    source = sources[digest]
                    self.assertEqual(hashlib.sha256(source['text'].encode('utf-8')).hexdigest(), digest)
                    self.assertEqual(texts.recognized_license(source['text']), source['identifier'])

    def test_changed_ancillary_restrictions_and_filename_only_refuse(self):
        for item in ANCILLARY:
            text = item['text']
            for changed in (text + '\nRedistribution is prohibited.\n', text[:len(text) // 2],
                            '\n' + text, item['member'], item['sha256']):
                with self.subTest(package=item['package'], changed=changed[-60:]):
                    self.assertIsNone(self.ancillary(changed))
        for text in ('SPDX-License-Identifier: MIT\n', 'AUTHORS.rst', 'NOTICE', 'LICENSE'):
            self.assertIsNone(self.ancillary(text))


if __name__ == '__main__':
    unittest.main()
