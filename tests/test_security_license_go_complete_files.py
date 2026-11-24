"""Go source text identity stays separate from module use and policy proof."""
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.security_license_texts import recognized_license, recognized_license_bundle

DATA = json.loads((ROOT / 'tests/fixtures/security-license-go-complete-files.json').read_text(encoding='utf-8'))


class GoCompleteLicenseFileTests(unittest.TestCase):
    def test_complete_exact_files_identify_only_existing_six_ids(self):
        for item in DATA['complete_files'] + DATA['already_recognized']:
            with self.subTest(sha256=item['sha256']):
                self.assertEqual(hashlib.sha256(item['text'].encode()).hexdigest(), item['sha256'])
                self.assertEqual(len(item['text'].encode()), item['bytes'])
                self.assertTrue(item['sources'])
                self.assertIn(item['identifier'], {'MIT', 'ISC', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD'})
                self.assertEqual(recognized_license(item['text']), item['identifier'])
                self.assertIsNone(recognized_license_bundle(item['text']))

    def test_each_changed_single_grant_truncated_file_and_extra_restriction_refuse(self):
        grants = {'MIT': r'without\s+restriction', 'ISC': r'without\s+fee',
                  'Apache-2.0': 'perpetual', 'BSD-2-Clause': r'are\s+permitted',
                  'BSD-3-Clause': r'are\s+permitted'}
        for item in DATA['complete_files']:
            text = item['text']
            changed, count = re.subn(grants[item['identifier']], 'PROHIBITED', text, count=1)
            self.assertEqual(count, 1)
            for label, mutant in [('grant', changed), ('tail', text[:len(text) // 2]),
                                  ('restriction', text + '\nRedistribution is prohibited.\n')]:
                with self.subTest(sha256=item['sha256'], mutant=label):
                    self.assertIsNone(recognized_license(mutant))
                    self.assertIsNone(recognized_license_bundle(mutant))

    def test_bundles_identify_all_distinct_grants_without_single_id_collapse(self):
        for item in DATA['bundles']:
            with self.subTest(sha256=item['sha256']):
                self.assertEqual(hashlib.sha256(item['text'].encode()).hexdigest(), item['sha256'])
                self.assertEqual(recognized_license_bundle(item['text']), tuple(item['identifiers']))
                self.assertIsNone(recognized_license(item['text']))

    def test_every_bundle_grant_and_entire_container_must_remain_intact(self):
        for item in DATA['bundles']:
            text = item['text']
            grants = list(re.finditer(r'without\s+restriction|without\s+fee|are\s+permitted|perpetual', text))
            self.assertGreaterEqual(len(grants), 2)
            mutants = [(f'grant-{index}', text[:m.start()] + 'PROHIBITED' + text[m.end():]) for index, m in enumerate(grants)]
            mutants += [('tail', text[:len(text) // 2]), ('extra', text + '\nInternal use only.\n'),
                        ('prefix', 'Internal use only.\n' + text), ('bytes', '\n' + text)]
            for label, mutant in mutants:
                with self.subTest(sha256=item['sha256'], mutant=label):
                    self.assertIsNone(recognized_license_bundle(mutant))
                    self.assertIsNone(recognized_license(mutant))

    def test_go_toolchains_share_exact_bsd_terms_without_supplying_patent_or_use_proof(self):
        item = next(item for item in DATA['complete_files'] if item['sha256'] == '911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad')
        self.assertEqual({s['toolchain'] for s in item['sources'] if 'toolchain' in s}, {'go1.26.6', 'go1.27.4'})
        self.assertEqual(recognized_license(item['text']), 'BSD-3-Clause')

    def test_mixed_incomplete_references_unicode_and_extra_views_remain_review_required(self):
        for item in DATA['review_required']:
            with self.subTest(sha256=item['sha256']):
                if item['sha256']=='d2571186acad91c8a3121fb31f1aa5963e82ccd08608d00cef3eb3f3a6c8ad38':
                    self.assertEqual(recognized_license(item['text']),'BSD-2-Clause-Views')
                    from getzilla.security_licenses import ALLOWED, _select_expression
                    with self.assertRaises(ValueError):
                        _select_expression('BSD-2-Clause-Views',list(ALLOWED))
                else:
                    self.assertIsNone(recognized_license(item['text']))
                self.assertIsNone(recognized_license_bundle(item['text']))


if __name__ == '__main__':
    unittest.main()
