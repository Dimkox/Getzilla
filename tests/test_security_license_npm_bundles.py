"""Finite whole-file bundles identify all terms without losing source notices."""
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import security_license_texts as texts

DATA = json.loads((ROOT / 'tests/fixtures/security-license-npm-bundles.json').read_text(encoding='utf-8'))
ORIGINAL = json.loads((ROOT / 'tests/fixtures/security-license-npm-complete-files.json').read_text(encoding='utf-8'))


class NpmLicenseBundleTests(unittest.TestCase):
    def bundle(self, text):
        self.assertTrue(callable(getattr(texts, 'recognized_license_bundle', None)), 'missing exact whole-file bundle API')
        return texts.recognized_license_bundle(text)

    def test_exact_complete_bundles_return_all_existing_ids_and_preserve_single_api(self):
        for item in DATA['bundles']:
            with self.subTest(sha256=item['sha256']):
                self.assertEqual(hashlib.sha256(item['text'].encode()).hexdigest(), item['sha256'])
                self.assertEqual(len(item['text'].encode()), item['bytes'])
                self.assertTrue(item['artifacts'])
                self.assertEqual(self.bundle(item['text']), tuple(item['identifiers']))
                self.assertIsNone(texts.recognized_license(item['text']))

    def test_each_grant_change_missing_tail_and_added_terms_refuse(self):
        for item in DATA['bundles']:
            text = item['text']
            grants = list(re.finditer('without restriction|without fee', text))
            self.assertEqual(len(grants), 2)
            mutations = [(f'grant-{index}', text[:m.start()] + 'with restriction' + text[m.end():])
                         for index, m in enumerate(grants)]
            mutations += [('tail', text[:len(text) // 2]),
                          ('prefix', 'Internal use only.\n' + text),
                          ('suffix', text + '\nRedistribution is prohibited.\n'),
                          ('bytes', '\n' + text)]
            for label, changed in mutations:
                with self.subTest(sha256=item['sha256'], mutant=label):
                    self.assertIsNone(self.bundle(changed))

    def test_complete_ownerless_mit_identifies_terms_without_inventing_holder(self):
        for item in DATA['ownerless_complete_files']:
            text = item['text']
            with self.subTest(sha256=item['sha256']):
                self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), item['sha256'])
                self.assertEqual(texts.recognized_license(text), 'MIT')
                self.assertIsNone(self.bundle(text))
                for changed in (text.replace('without restriction', 'with restriction'),
                                text[:len(text) // 2], text + '\nInternal use only.\n'):
                    self.assertIsNone(texts.recognized_license(changed))

    def test_apache_only_protobuf_cannot_satisfy_metadata_bsd_terms(self):
        item = next(item for item in ORIGINAL['complete_files'] if item['sha256'] == DATA['protobuf_note']['sha256'])
        self.assertEqual(texts.recognized_license(item['text']), 'Apache-2.0')
        self.assertIsNone(self.bundle(item['text']))

    def test_bundles_never_match_general_substrings_filenames_or_new_license_terms(self):
        for text in ['LICENSE', 'SPDX-License-Identifier: MIT AND ISC\n'] + [item['text'] for item in ORIGINAL['review_required'] if item['text'] is not None]:
            with self.subTest(text=text[:55]):
                if hashlib.sha256(text.encode()).hexdigest() in {
                        '8a1af140fdfbf5afd3df27f7e662f989c5b963a300020dfafce42033cae9e004',
                        '2c7c5d22ed5a8ee968c64757710979afcd77438c48b4a265b94e615babd8a901'}:
                    self.assertEqual(self.bundle(text),('BlueOak-1.0.0',))
                    from getzilla.security_licenses import ALLOWED, _select_expression
                    with self.assertRaises(ValueError):
                        _select_expression('BlueOak-1.0.0',list(ALLOWED))
                else:
                    self.assertIsNone(self.bundle(text))


if __name__ == '__main__':
    unittest.main()
