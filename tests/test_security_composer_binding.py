"""Composer input binding, not installation or execution of a source project."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import known_vulns as inventory  # noqa: E402


class ComposerBindingTests(unittest.TestCase):
    def sample(self):
        return ((ROOT / 'examples/bitrix-module/composer.json').read_text(),
                (ROOT / 'examples/bitrix-module/composer.lock').read_text())

    def collect(self, manifest, lock):
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
            root = Path(directory)
            (root / 'composer.json').write_text(manifest)
            if lock is not None:
                (root / 'composer.lock').write_text(lock)
            return inventory.dependency_inventory(root, inventory.load_config(root))

    def test_actual_sample_lock_binds_both_inputs_and_all_packages(self):
        manifest, lock = self.sample()
        packages = json.loads(lock)['packages'] + json.loads(lock)['packages-dev']
        dependencies, _, proof = self.collect(manifest, lock)
        self.assertTrue(proof['complete'])
        self.assertEqual({row['path'] for row in proof['inputs']}, {'composer.json', 'composer.lock'})
        self.assertEqual({(d.name, d.version) for d in dependencies},
                         {(p['name'], p['version'].removeprefix('v')) for p in packages})

    def test_missing_stale_and_direct_dependency_omissions_refuse(self):
        manifest, lock = self.sample()
        document = json.loads(manifest)
        document['require-dev']['phpunit/phpunit'] = '^12.0'
        with self.assertRaises(inventory.VulnerabilityError):
            self.collect(json.dumps(document), lock)
        with self.assertRaises(inventory.VulnerabilityError):
            self.collect(manifest, None)
        data = json.loads(lock)
        data['packages-dev'] = [p for p in data['packages-dev'] if p['name'] != 'phpunit/phpunit']
        with self.assertRaises(inventory.VulnerabilityError):
            self.collect(manifest, json.dumps(data))

    def test_fresh_hash_cannot_hide_wrong_version_section_or_duplicate(self):
        manifest, lock = self.sample()
        for mutation in ('version', 'section', 'duplicate', 'platform', 'alias'):
            document, data = json.loads(manifest), json.loads(lock)
            if mutation == 'version':
                document['require-dev']['phpunit/phpunit'] = '^12.0'
            elif mutation == 'section':
                document['require']['phpunit/phpunit'] = document['require-dev'].pop('phpunit/phpunit')
            elif mutation == 'duplicate':
                data['packages'] = [copy.deepcopy(data['packages-dev'][0])]
            elif mutation == 'platform':
                data['platform']['php'] = '>=9.0'
            else:
                data['aliases'] = [{'package': 'phpunit/phpunit', 'alias': '12.0'}]
            text = json.dumps(document)
            data['content-hash'] = inventory._composer_content_hash(text)
            with self.subTest(mutation=mutation), self.assertRaises(inventory.VulnerabilityError):
                self.collect(text, json.dumps(data))

    def test_nonresolution_edits_still_change_full_input_proof(self):
        manifest, lock = self.sample()
        before = self.collect(manifest, lock)[2]
        data = json.loads(manifest)
        data['scripts']['test'] = 'owned inert script text; never execute'
        after = self.collect(json.dumps(data), lock)[2]
        self.assertNotEqual(before['inputs'], after['inputs'])

    def test_native_composer_content_hash_anchor_and_empty_object_encoding(self):
        manifest, _ = self.sample()
        self.assertEqual(inventory._composer_content_hash(manifest), '5731440dcb92ec168b90b403f077a8b3')
        self.assertEqual(inventory._composer_content_hash('{}'), 'd751713988987e9331980363e24189ce')
        self.assertEqual(inventory._composer_content_hash('{"require":{}}'),
                         inventory._composer_content_hash('{"require":[]}'))

    def test_supported_stable_constraint_boundaries(self):
        for version, constraint, expected in (
                ('11.5.58', '^11.0', True), ('12.0.0', '^11.0', False),
                ('0.2.9', '^0.2', True), ('0.3.0', '^0.2', False),
                ('0.0.3', '^0.0', True), ('0.1.0', '^0.0', False),
                ('0.0.3', '^0.0.3', True), ('0.0.4', '^0.0.3', False),
                ('1.9.0', '~1.2', True), ('2.0.0', '~1.2', False),
                ('1.2.9', '~1.2.3', True), ('1.3.0', '~1.2.3', False),
                ('v1.2.3', '1.2.3', True), ('1.2.4', '1.2.3', False)):
            with self.subTest(version=version, constraint=constraint):
                self.assertEqual(inventory._composer_satisfies(version, constraint), expected)

    def test_missing_hash_duplicate_keys_and_unsupported_graphs_remain_closed(self):
        manifest, lock = self.sample()
        for mutation in ('hash', 'duplicate-key', 'alternative', 'replace', 'repository', 'bad-platform', 'bad-policy', 'bad-stability'):
            document, data = json.loads(manifest), json.loads(lock)
            if mutation == 'alternative':
                document['require-dev']['phpunit/phpunit'] = '^11.0 || ^12.0'
            elif mutation == 'replace':
                document['replace'] = {'phpunit/phpunit': '*'}
            elif mutation == 'repository':
                document['repositories'] = [{'type': 'composer', 'url': 'https://example.invalid/'}]
            elif mutation == 'bad-platform':
                document['require']['php'] = 'unresolved'
                data['platform']['php'] = 'unresolved'
            elif mutation == 'bad-policy':
                document['prefer-stable'] = 'unresolved'
            elif mutation == 'bad-stability':
                document['minimum-stability'] = []
            text = json.dumps(document)
            data['content-hash'] = inventory._composer_content_hash(text)
            if mutation == 'hash':
                del data['content-hash']
            encoded = json.dumps(data)
            if mutation == 'duplicate-key':
                encoded = encoded[:-1] + ',"packages":[]}'
            with self.subTest(mutation=mutation), self.assertRaises(inventory.VulnerabilityError):
                self.collect(text, encoded)

    def test_unrelated_lock_and_linked_inputs_cannot_cover_manifest(self):
        manifest, lock = self.sample()
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
            root = Path(directory)
            (root / 'composer.json').write_text(manifest)
            (root / 'other').mkdir()
            (root / 'other/composer.lock').write_text(lock)
            with self.assertRaises(inventory.VulnerabilityError):
                inventory.dependency_inventory(root, inventory.load_config(root))
            (root / 'composer.lock').symlink_to('other/composer.lock')
            with self.assertRaises(inventory.VulnerabilityError):
                inventory.dependency_inventory(root, inventory.load_config(root))

    def test_pair_custody_is_rechecked_after_binding(self):
        manifest, lock = self.sample()
        with tempfile.TemporaryDirectory(dir=ROOT / '.getzilla/runtime') as directory:
            root = Path(directory)
            (root / 'composer.json').write_text(manifest)
            (root / 'composer.lock').write_text(lock)
            validate = inventory._validate_composer_binding
            def change_after_validation(*args):
                validate(*args)
                (root / 'composer.lock').write_text(lock + '\n')
            with mock.patch.object(inventory, '_validate_composer_binding', side_effect=change_after_validation), \
                    self.assertRaises(inventory.VulnerabilityError):
                inventory.dependency_inventory(root, inventory.load_config(root))


if __name__ == '__main__':
    unittest.main()
