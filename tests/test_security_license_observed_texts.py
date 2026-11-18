"""Complete real wheel license variants retain attribution and every term."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.security_license_texts import recognized_license

FIXTURES = json.loads((ROOT / 'tests/fixtures/security-license-observed-variants.json').read_text(encoding='utf-8'))


class ObservedLicenseTextTests(unittest.TestCase):
    def test_complete_reviewed_wheel_files_match_existing_identifiers(self):
        for item in FIXTURES:
            with self.subTest(package=item['package']):
                self.assertEqual(hashlib.sha256(item['text'].encode('utf-8')).hexdigest(), item['sha256'])
                self.assertEqual(recognized_license(item['text']), item['identifier'])

    def test_added_restrictions_and_changed_or_truncated_terms_refuse(self):
        for item in FIXTURES:
            text = item['text']
            self.assertIn('"AS IS"', text)
            for changed in (text + '\nRedistribution is prohibited.\n', text[:len(text) // 2],
                            text.replace('"AS IS"', '"AS AVAILABLE"'),
                            text.replace('prior written permission', 'prior oral permission')
                            if item['identifier'] == 'BSD-3-Clause' else
                            text.replace('free of charge', 'for a fee')):
                with self.subTest(package=item['package'], changed=changed[-80:]):
                    self.assertIsNone(recognized_license(changed))

    def test_unknown_text_and_identifier_only_do_not_gain_recognition(self):
        for text in ('Unreviewed license terms.\n', 'SPDX-License-Identifier: MIT\n',
                     'SPDX-License-Identifier: MPL-2.0\n', 'SPDX-License-Identifier: PSF-2.0\n'):
            with self.subTest(text=text):
                self.assertIsNone(recognized_license(text))

    def test_terms_without_retained_attribution_refuse(self):
        for item in FIXTURES:
            start = 'Permission is hereby granted' if item['identifier'] == 'MIT' else 'Redistribution and use'
            body = item['text'][item['text'].index(start):]
            with self.subTest(package=item['package']):
                self.assertIsNone(recognized_license(body))


if __name__ == '__main__':
    unittest.main()
