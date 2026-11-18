"""Only reviewed complete source bytes qualify the finite NPM variants."""
import base64
import hashlib
import json
import re
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.security_license_texts import recognized_license

FIXTURES = json.loads((ROOT / 'tests/fixtures/security-license-npm-complete-files.json').read_text(encoding='utf-8'))


class NpmCompleteLicenseFileTests(unittest.TestCase):
    def test_reviewed_complete_files_match_existing_six_identifiers(self):
        for item in FIXTURES['complete_files']:
            with self.subTest(sha256=item['sha256']):
                body = item['text'].encode('utf-8')
                self.assertEqual(hashlib.sha256(body).hexdigest(), item['sha256'])
                self.assertEqual(len(body), item['bytes'])
                self.assertTrue(item['artifacts'])
                self.assertIn(item['identifier'], {'MIT', 'ISC', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD'})
                self.assertEqual(recognized_license(item['text']), item['identifier'])

    def test_changed_operative_terms_truncation_and_added_restriction_refuse(self):
        replacements = {'MIT': ('without restriction', 'with restriction'),
                        'ISC': ('without fee', 'with fee'),
                        '0BSD': ('without fee', 'with fee'),
                        'Apache-2.0': ('perpetual', 'temporary'),
                        'BSD-2-Clause': ('are permitted', 'are prohibited'),
                        'BSD-3-Clause': ('are permitted', 'are prohibited')}
        for item in FIXTURES['complete_files']:
            text = item['text']
            before, after = replacements[item['identifier']]
            pattern = r'\s+'.join(re.escape(word) for word in before.split())
            changed_grant, count = re.subn(pattern, after, text, count=1)
            self.assertEqual(count, 1)
            for label, changed in [('grant', changed_grant),
                                   ('truncated', text[:len(text) // 2]),
                                   ('restriction', text + '\nRedistribution is prohibited.\n')]:
                with self.subTest(sha256=item['sha256'], mutant=label):
                    self.assertIsNone(recognized_license(changed))

    def test_compound_ancillary_new_license_and_missing_attribution_remain_review_required(self):
        for item in FIXTURES['review_required']:
            with self.subTest(sha256=item['sha256'], category=item['review_category']):
                body = item['text'].encode('utf-8') if item['text'] is not None else base64.b64decode(item['base64'], validate=True)
                self.assertEqual(hashlib.sha256(body).hexdigest(), item['sha256'])
                self.assertEqual(len(body), item['bytes'])
                if item['text'] is not None:
                    self.assertIsNone(recognized_license(item['text']))

    def test_readme_container_does_not_create_a_general_substring_exception(self):
        item = next(item for item in FIXTURES['complete_files'] if item['path'] == 'package/README.md')
        text = item['text']
        self.assertTrue(text.startswith('\n# isarray\n'))
        self.assertIsNone(recognized_license('Additional restriction: internal use only.\n' + text))
        self.assertIsNone(recognized_license(text.replace('## Usage', '## Usage for internal use only')))
        self.assertIsNone(recognized_license('README.md'))


if __name__ == '__main__':
    unittest.main()
