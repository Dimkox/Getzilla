from __future__ import annotations

import tempfile
import hashlib
import json
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from getzilla.security_inventory import collect_inventory

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)
IMAGE = 'postgres@sha256:' + 'a' * 64
ACTION = 'actions/checkout@' + 'b' * 40
CONSTRUCTED = []


def forbidden_yaml_constructor():
    CONSTRUCTED.append('executed')
    return {}


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


class StructuralYamlInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='security-yaml-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.environment = mock.patch.dict(os.environ, {'GIT_CEILING_DIRECTORIES': str(self.root.parent)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.inputs = set()

    def fixture(self, path, text, **kwargs):
        for previous in self.inputs:
            previous.unlink()
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8', newline='\n')
        self.inputs = {target}
        inventory = collect_inventory(self.root, **kwargs)
        if path.endswith(('.yaml', '.yml')) and 'fixtures' not in Path(path).parts and len(text.encode()) <= 1024 * 1024:
            self.assertIn({'path': path, 'sha256': hashlib.sha256(text.encode()).hexdigest()}, inventory['manifests'])
        return inventory

    def consumers(self):
        from getzilla.expanded_security import run_checks, security_obligations
        planned = {item['check_id']: item for item in security_obligations(self.root, environ={}, now=NOW)}
        checked = {item['name']: item for item in run_checks(self.root, environ={}, now=NOW)}
        return planned, checked

    def assert_required_blocked(self, *names):
        planned, checked = self.consumers()
        for name in names:
            self.assertEqual(planned[name]['applicability'], 'required', (name, planned))
            self.assertEqual(checked[name]['status'], 'fail', (name, checked))
            self.assertEqual(checked[name]['details'][0]['outcome'], 'blocked', (name, checked))

    def assert_incomplete(self, inventory):
        self.assertFalse(inventory['complete'], inventory)
        self.assertTrue(inventory['gaps'])
        self.assert_required_blocked('security-inventory', 'security-container-images', 'security-licenses',
                                     'security-kev', 'security-epss', 'security-malicious-packages')

    def test_compose_block_flow_and_decoded_quoted_keys_have_the_same_image_obligations(self):
        variants = [f'services:\n  db:\n    image: {IMAGE}\n',
                    f'services: {{db: {{image: "{IMAGE}"}}}}\n',
                    f'"services": {{"db": {{"image": "{IMAGE}"}}}}\n',
                    f"'services':\n  'db':\n    'image': '{IMAGE}'\n",
                    f'"serv\\u0069ces": {{db: {{"im\\u0061ge": "{IMAGE}"}}}}\n']
        for text in variants:
            with self.subTest(text=text):
                inventory = self.fixture('compose.yaml', text)
                self.assertTrue(inventory['complete'], inventory)
                self.assertEqual([item['reference'] for item in inventory['images']], [IMAGE])
                self.assertGreater(inventory['images'][0]['line'], 0)
                self.assert_required_blocked('security-container-images', 'security-kev', 'security-epss', 'security-licenses')

    def test_compose_override_names_do_not_hide_the_same_structural_model(self):
        for path in ('docker-compose.override.yml', 'docker-compose.production.yaml', 'compose.override.yml'):
            with self.subTest(path=path):
                inventory = self.fixture(path, f'services: {{db: {{image: "{IMAGE}"}}}}\n')
                self.assertTrue(inventory['complete'], inventory)
                self.assertEqual([item['reference'] for item in inventory['images']], [IMAGE])
                self.assert_required_blocked('security-container-images', 'security-licenses')

    def test_actions_step_block_flow_and_quoted_keys_retain_tools(self):
        variants = [f'jobs:\n  scan:\n    steps:\n      - uses: {ACTION}\n',
                    f'jobs: {{scan: {{steps: [{{uses: "{ACTION}"}}]}}}}\n',
                    f'"jobs": {{"scan": {{"steps": [{{"uses": "{ACTION}"}}]}}}}\n',
                    f"jobs:\n  scan:\n    steps:\n      - 'uses': '{ACTION}'\n"]
        for text in variants:
            with self.subTest(text=text):
                inventory = self.fixture('.github/workflows/check.yml', text)
                self.assertTrue(inventory['complete'], inventory)
                self.assertEqual([item['reference'] for item in inventory['tools']], [ACTION])
                self.assert_required_blocked('security-licenses')

    def test_actions_job_container_string_object_and_service_images_are_inventoried(self):
        variants = [f'jobs:\n  scan:\n    container: {IMAGE}\n    steps: [{{run: echo ok}}]\n',
                    f'jobs:\n  scan:\n    container:\n      image: "{IMAGE}"\n    steps: []\n',
                    f'jobs: {{scan: {{container: "{IMAGE}", steps: []}}}}\n',
                    f'jobs: {{scan: {{container: {{image: "{IMAGE}"}}, steps: []}}}}\n',
                    f'jobs:\n  scan:\n    services:\n      db:\n        image: {IMAGE}\n    steps: []\n',
                    f'"jobs": {{scan: {{"services": {{db: {{"image": "{IMAGE}"}}}}, steps: []}}}}\n']
        for text in variants:
            with self.subTest(text=text):
                inventory = self.fixture('.github/workflows/check.yml', text)
                self.assertTrue(inventory['complete'], inventory)
                self.assertEqual([item['reference'] for item in inventory['images']], [IMAGE])
                self.assert_required_blocked('security-container-images', 'security-kev', 'security-epss', 'security-licenses')

    def test_docker_action_is_an_image(self):
        for reference in ('docker://' + IMAGE, 'docker://postgres:latest'):
            inventory = self.fixture('.github/workflows/check.yml', f'jobs: {{scan: {{steps: [{{uses: "{reference}"}}]}}}}\n')
            self.assertEqual([item['reference'] for item in inventory['images']], [reference.removeprefix('docker://')])
            self.assertEqual(inventory['complete'], reference.endswith('a' * 64))
            self.assert_required_blocked('security-container-images', 'security-licenses')

    def test_reusable_or_local_actions_are_unresolved_composition(self):
        for reference in ('./.github/actions/local', './.github/workflows/reusable.yml',
                          '$/.github/workflows/reusable.yml',
                          'owner/repo/.github/workflows/reusable.yml@' + 'c' * 40):
            for direct_job in (False, True):
                with self.subTest(reference=reference, direct_job=direct_job):
                    text = (f'jobs: {{scan: {{uses: "{reference}"}}}}\n' if direct_job else
                            f'jobs: {{scan: {{steps: [{{uses: "{reference}"}}]}}}}\n')
                    inventory = self.fixture('.github/workflows/check.yml', text)
                    self.assertEqual([item['reference'] for item in inventory['tools']], [reference])
                    self.assert_incomplete(inventory)

    def test_compose_indirection_does_not_establish_absence_even_with_a_visible_image(self):
        variants = ['include: [other.yml]\n', 'services: {api: {extends: {file: other.yml, service: api}}}\n',
                    'services: {api: {build: .}}\n',
                    f'services: {{api: {{image: "{IMAGE}", build: {{context: ., dockerfile: custom.build}}}}}}\n',
                    'services: {api: {build: {context: https://example.invalid/repo.git}}}\n']
        for text in variants:
            with self.subTest(text=text):
                self.assert_incomplete(self.fixture('compose.yaml', text))

    def test_anchors_aliases_merges_duplicate_keys_tags_and_multiple_documents_refuse(self):
        variants = [f'x-base: &base {{image: "{IMAGE}"}}\nservices: {{db: *base}}\n',
                    f'services:\n  db: &base\n    image: {IMAGE}\n  other:\n    <<: *base\n',
                    f'services: {{db: {{<<: {{image: "{IMAGE}"}}}}}}\n',
                    f'services: {{}}\n"services": {{db: {{image: "{IMAGE}"}}}}\n',
                    f'services: {{db: {{image: "{IMAGE}", "image": "{IMAGE}"}}}}\n',
                    'services: !unqualified {}\n',
                    '!!python/object/apply:tests.test_security_inventory.forbidden_yaml_constructor []\n',
                    f'services: {{}}\n---\nservices: {{db: {{image: "{IMAGE}"}}}}\n',
                    '%YAML 1.1\n---\nservices: {}\n']
        before = list(CONSTRUCTED)
        for text in variants:
            with self.subTest(text=text):
                self.assert_incomplete(self.fixture('compose.yaml', text))
        self.assertEqual(CONSTRUCTED, before, 'YAML parser must never invoke object construction')

    def test_dynamic_mutable_missing_and_unsupported_types_cannot_be_empty_complete(self):
        fixtures = [
            ('compose.yaml', 'services: [db]\n'), ('compose.yaml', 'services: {db: null}\n'),
            ('compose.yaml', 'services: {db: {image: [postgres]}}\n'),
            ('compose.yaml', 'services: {db: {image: postgres:latest}}\n'),
            ('compose.yaml', 'services: {db: {image: "${IMAGE}"}}\n'),
            ('compose.yaml', 'services: {db: {image: 123}}\n'),
            ('compose.yaml', 'services: {db: {command: echo}}\n'),
            ('.github/workflows/check.yml', 'jobs: [scan]\n'),
            ('.github/workflows/check.yml', 'jobs: {scan: null}\n'),
            ('.github/workflows/check.yml', 'jobs: {scan: {container: false}}\n'),
            ('.github/workflows/check.yml', 'jobs: {scan: {container: {options: --rm}}}\n'),
            ('.github/workflows/check.yml', 'jobs: {scan: {services: []}}\n'),
            ('.github/workflows/check.yml', 'jobs: {scan: {steps: {uses: local}}}\n'),
            ('.github/workflows/check.yml', 'jobs: {scan: {steps: [null]}}\n'),
            ('.github/workflows/check.yml', 'jobs: {scan: {steps: [{uses: [actions/checkout]}]}}\n'),
            ('.github/workflows/check.yml', 'jobs: {scan: {steps: [{uses: "actions/checkout@main"}]}}\n'),
            ('.github/workflows/check.yml', 'jobs: {scan: {container: "${{ matrix.image }}"}}\n'),
            ('.github/workflows/check.yml', 'jobs: {scan: {steps: [{uses: "${{ inputs.action }}"}]}}\n'),
        ]
        for path, text in fixtures:
            with self.subTest(path=path, text=text):
                self.assert_incomplete(self.fixture(path, text))

    def test_yaml_limits_are_fail_closed_without_recursive_alias_expansion(self):
        variants = [('# ' + 'x' * (1024 * 1024) + '\njobs: {}\n', 'bound|limit'),
                    ('name: "' + 'x' * 65537 + '"\njobs: {}\n', 'scalar|limit'),
                    ('env: ' + '[' * 70 + '0' + ']' * 70 + '\njobs: {}\n', 'depth|limit'),
                    ('env: [' + ','.join(['0'] * 20001) + ']\njobs: {}\n', 'node|limit')]
        for text, message in variants:
            with self.subTest(bound=message):
                inventory = self.fixture('.github/workflows/check.yml', text)
                self.assert_incomplete(inventory)
                self.assertRegex(' '.join(gap['message'] for gap in inventory['gaps']), message)

    def test_parser_missing_blocks_only_relevant_yaml_and_preserves_ignored_fixtures(self):
        with mock.patch.dict(sys.modules, {'yaml': None}):
            plain = self.fixture('src/main.py', 'print("hello")\n')
            self.assertTrue(plain['complete'], plain)
            ignored = self.fixture('tests/fixtures/compose.yaml', 'services: {db: {image: unsafe}}\n')
            self.assertTrue(ignored['complete'], ignored)
            self.assertIn('tests/fixtures/compose.yaml', ignored['excluded_fixture_paths'])
            inventory = self.fixture('compose.yaml', f'services: {{db: {{image: "{IMAGE}"}}}}\n')
            self.assert_incomplete(inventory)
            self.assertIn('yaml-parser-unavailable', {gap['code'] for gap in inventory['gaps']})

    def test_incompatible_parser_interface_is_an_explicit_gap(self):
        incompatible = SimpleNamespace(parse=None, BaseLoader=None, events=None, YAMLError=ValueError)
        with mock.patch.dict(sys.modules, {'yaml': incompatible}):
            try:
                inventory = self.fixture('compose.yaml', 'services: {}\n')
            except (AttributeError, TypeError) as exc:
                self.fail(f'parser capability failure must be a structured inventory gap: {type(exc).__name__}')
            self.assert_incomplete(inventory)
            self.assertIn('yaml-parser-unavailable', {gap['code'] for gap in inventory['gaps']})

    def test_run_scalars_decode_downloads_without_becoming_structural_uses(self):
        text = f'jobs: {{scan: {{steps: [{{run: "echo uses: {ACTION}"}}]}}}}\n'
        control = self.fixture('.github/workflows/check.yml', text)
        self.assertTrue(control['complete'], control)
        self.assertEqual(control['tools'], [])
        self.assertEqual(control['images'], [])
        text = 'jobs: {scan: {steps: [{run: "c\\u0075rl https://example.invalid/tool"}]}}\n'
        inventory = self.fixture('.github/workflows/check.yml', text)
        self.assert_incomplete(inventory)
        self.assertEqual([item['kind'] for item in inventory['tools']], ['script-download'])
        self.assertTrue(inventory['tools'][0]['reference'].startswith('curl '))

    def test_exact_yaml_bytes_bind_inventory_even_when_objects_are_equal(self):
        text = f'services: {{db: {{image: "{IMAGE}"}}}}\n'
        first = self.fixture('compose.yaml', text)
        second = self.fixture('compose.yaml', '# source changed\n' + text)
        self.assertEqual([item['reference'] for item in first['images']], [IMAGE])
        self.assertEqual([item['reference'] for item in second['images']], [IMAGE])
        self.assertNotEqual(first['digest'], second['digest'])
        self.assertNotEqual(first['manifests'], second['manifests'])

    def test_isolated_cli_and_checker_obligations_keep_flow_image_required_and_blocked(self):
        from getzilla.expanded_security import security_obligations
        from getzilla.security_cli import evaluate
        inventory = self.fixture('compose.yaml', f'services: {{db: {{image: "{IMAGE}"}}}}\n')
        source = {'head_sha': 'a' * 40, 'tree_sha': 'b' * 40, 'checker_sha': 'c' * 40,
                  'checker_tree_sha': 'd' * 40, 'candidate_clean': True, 'checker_clean': True,
                  'same_project': True}
        runtime = self.root / '.getzilla/runtime'
        # Only native Git identities are fixture inputs. All inventory,
        # local security producers and final CLI aggregation run normally.
        with mock.patch('getzilla.security_cli.source_binding', return_value=source):
            report = evaluate(self.root, runtime / 'db', runtime / 'artifacts', runtime / 'tools', now=NOW)
        self.assertEqual(report['status'], 'fail')
        images = next(item for item in report['checks'] if item['name'] == 'security-container-images')
        self.assertEqual(images['details'][0]['outcome'], 'blocked')
        obligations = security_obligations(self.root, inventory=inventory, environ={}, now=NOW)
        image_obligation = next(item for item in obligations if item['check_id'] == 'security-container-images')
        self.assertEqual(image_obligation['applicability'], 'required')
        self.assertEqual(image_obligation['evidence']['inventory_sha256'], inventory['digest'])


if __name__ == '__main__':
    unittest.main()
