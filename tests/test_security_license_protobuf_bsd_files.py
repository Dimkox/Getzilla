"""Four exact decoded BSD blocks identify terms; the source reader owns decoding."""
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla.security_license_texts import recognized_license, recognized_license_bundle

DATA = json.loads((ROOT / 'tests/fixtures/security-license-protobuf-bsd-files.json').read_text(encoding='utf-8'))


class ProtobufBsdTextTests(unittest.TestCase):
    def test_four_complete_decoded_blocks_identify_bsd3_with_original_source_bindings(self):
        self.assertEqual(len(DATA['complete_files']), 4)
        self.assertEqual(sum(len(item['sources']) for item in DATA['complete_files']), 12)
        for item in DATA['complete_files']:
            with self.subTest(sha256=item['sha256']):
                self.assertEqual(hashlib.sha256(item['text'].encode()).hexdigest(), item['sha256'])
                self.assertEqual(len(item['text'].encode()), item['bytes'])
                self.assertEqual(recognized_license(item['text']), 'BSD-3-Clause')
                self.assertIsNone(recognized_license_bundle(item['text']))
                for source in item['sources']:
                    self.assertRegex(source['artifact_sha256'], r'^[0-9a-f]{64}$')
                    self.assertRegex(source['container_sha256'], r'^[0-9a-f]{64}$')
                    self.assertGreater(source['selector']['end_line_exclusive'], source['selector']['start_line'])

    def test_changed_grant_truncated_terms_and_added_restrictions_refuse(self):
        for item in DATA['complete_files']:
            text = item['text']
            changed, count = re.subn(r'are\s+permitted', 'are prohibited', text, count=1)
            self.assertEqual(count, 1)
            for label, mutant in [('grant', changed), ('truncated', text[:len(text) // 2]),
                                  ('extra', text + '\nInternal use only.\n')]:
                with self.subTest(sha256=item['sha256'], mutant=label):
                    self.assertIsNone(recognized_license(mutant))

    def test_helper_does_not_strip_comments_extract_partial_blocks_or_ignore_changed_prose(self):
        for item in DATA['complete_files']:
            text = item['text']
            for label, mutant in [('comment-container', '// ' + text.replace('\n', '\n// ')),
                                  ('prefix', '/*\n' + text + '\n*/'),
                                  ('bytes', '\n' + text),
                                  ('prose', text + 'Different generated-code conditions.\n')]:
                with self.subTest(sha256=item['sha256'], mutant=label):
                    self.assertIsNone(recognized_license(mutant))

    def test_apache_only_protobuf_file_still_supplies_only_apache_terms(self):
        original = json.loads((ROOT / 'tests/fixtures/security-license-npm-complete-files.json').read_text(encoding='utf-8'))
        item = next(item for item in original['complete_files'] if item['sha256'] == '5e3400b93bbb099e83e52bab885e7441750673c21f97988ca3f1240639b63283')
        self.assertEqual(recognized_license(item['text']), 'Apache-2.0')
        self.assertIsNone(recognized_license_bundle(item['text']))


if __name__ == '__main__':
    unittest.main()
