from __future__ import annotations

import tempfile
import json
import unittest
from pathlib import Path

from getzilla.security_inventory import collect_inventory


class InventoryTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='security-inventory-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def put(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')

    def test_unpinned_dependency_does_not_hide_behind_another_exact_pin(self):
        self.put('requirements.txt', 'safe==1.0.0\nother>=2\n')
        inventory = collect_inventory(self.root)
        self.assertEqual(inventory['dependencies'][0]['name'], 'safe')
        self.assertFalse(inventory['complete'])
        self.assertIn('unresolved-dependency', {gap['code'] for gap in inventory['gaps']})

    def test_nested_images_and_unknown_source_formats_are_not_no_objects(self):
        self.put('services/api/Dockerfile', 'FROM postgres:17-alpine\n')
        self.put('other/pom.xml', '<project/>\n')
        inventory = collect_inventory(self.root)
        self.assertEqual(inventory['images'][0]['reference'], 'postgres:17-alpine')
        self.assertFalse(inventory['complete'])
        self.assertIn('unsupported-manifest', {gap['code'] for gap in inventory['gaps']})

    def test_stage_alias_does_not_hide_the_base_image_it_is_defining(self):
        self.put('Dockerfile', 'FROM postgres AS postgres\nFROM postgres AS final\n')
        inventory = collect_inventory(self.root)
        self.assertEqual([item['reference'] for item in inventory['images']], ['postgres'])

    def test_ci_image_config_is_scanned_and_invalid_pins_are_inventory_gaps(self):
        self.put('.getzilla/config/ci-images.json', json.dumps({
            'schema_version': 1, 'platform': 'linux/amd64',
            'postgres': {'reference': 'postgres@sha256:' + 'a' * 64,
                         'image_id': 'sha256:' + 'b' * 64, 'source': 'https://example.invalid/pin'},
            'python': {'reference': 'python:latest'}}))
        inventory = collect_inventory(self.root)
        self.assertEqual(len(inventory['images']), 1)
        self.assertEqual(inventory['images'][0]['reference'], 'postgres@sha256:' + 'a' * 64)
        self.assertIn('unresolved-image', {gap['code'] for gap in inventory['gaps']})

    def test_build_dependencies_are_included_even_without_runtime_dependencies(self):
        self.put('delivery/pyproject.toml', '[build-system]\nrequires=["setuptools==84.1.0"]\n[project]\nname="fixture"\ndependencies=[]\n')
        inventory = collect_inventory(self.root)
        self.assertEqual([(d['name'], d['version'], d['usage']) for d in inventory['dependencies']],
                         [('setuptools', '84.1.0', 'build')])
        self.assertTrue(inventory['complete'])

    def test_no_manifest_is_proven_by_file_inventory_and_changes_invalidate_digest(self):
        self.put('src/main.py', 'print("hello")\n')
        before = collect_inventory(self.root)
        self.assertTrue(before['complete'])
        self.assertEqual(before['dependencies'], [])
        self.assertEqual(before['images'], [])
        self.put('services/requirements.txt', 'added==1.0.0\n')
        after = collect_inventory(self.root)
        self.assertNotEqual(before['digest'], after['digest'])
        self.assertEqual(after['dependencies'][0]['name'], 'added')

    def test_fixture_exclusions_are_explicit_and_do_not_exclude_real_build_inputs(self):
        self.put('tests/fixtures/requirements.txt', 'synthetic>=999\n')
        self.put('.getzilla/config/python-quality-requirements.txt', 'bandit==1.9.4\n')
        inventory = collect_inventory(self.root)
        self.assertTrue(inventory['complete'])
        self.assertEqual([d['name'] for d in inventory['dependencies']], ['bandit'])
        self.assertIn('tests/fixtures/requirements.txt', inventory['excluded_fixture_paths'])

    def test_empty_lock_does_not_resolve_nonempty_direct_manifest(self):
        self.put('package.json', '{"dependencies":{"missing":"^1.0.0"}}')
        self.put('package-lock.json', '{"lockfileVersion":3,"packages":{}}')
        inventory = collect_inventory(self.root)
        self.assertFalse(inventory['complete'])
        self.assertIn('unresolved-dependency', {gap['code'] for gap in inventory['gaps']})

    def test_image_variables_need_exact_observed_binding_and_actions_are_inventoried(self):
        self.put('service/compose.yaml', 'services:\n  db:\n    image: ${DB_IMAGE:?set immutable image}\n')
        self.put('.github/workflows/check.yml', 'jobs:\n  test:\n    steps:\n      - uses: actions/checkout@' + 'a' * 40 + '\n')
        unknown = collect_inventory(self.root)
        self.assertFalse(unknown['complete'])
        self.assertEqual(len(unknown['tools']), 1)
        observed = collect_inventory(self.root, image_bindings={'DB_IMAGE': 'postgres@sha256:' + 'b' * 64})
        self.assertTrue(observed['complete'])
        self.assertEqual(observed['images'][0]['reference'], 'postgres@sha256:' + 'b' * 64)


if __name__ == '__main__':
    unittest.main()
