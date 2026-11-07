"""Explicit public local fixtures for the optional design-reference child."""
from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))


def load_file(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class LocalDesignReferenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def extractor(self):
        path = ROOT / '.getzilla/optional-modules/design-reference/0.1.0/reference.py'
        self.assertTrue(path.is_file(), 'explicit local design-reference artifact is missing')
        return load_file(path, 'public_design_reference')

    def capture(self, module, files, capture_id='capture-a'):
        return module.capture(self.root, files, capture_id=capture_id,
                              captured_at='2026-11-07T00:00:00Z')

    def test_json_css_preserve_raw_units_locators_and_repeatable_content(self):
        module = self.extractor()
        (self.root / 'tokens.json').write_text('{"space":{"small":"8px"},"weight":700}')
        (self.root / 'theme.css').write_text(':root { --accent: #123456; --gap: 1.25rem; }')
        first = self.capture(module, ['tokens.json', 'theme.css'])
        second = self.capture(module, ['theme.css', 'tokens.json'], 'capture-b')
        self.assertEqual(first['content_digest'], second['content_digest'])
        self.assertNotEqual(first['capture'], second['capture'])
        self.assertEqual(first['content']['coverage']['status'], 'complete')
        tokens = first['content']['tokens']
        self.assertEqual({(x['raw_value'], x['unit']) for x in tokens},
                         {('8px', 'px'), ('700', None), ('#123456', None), ('1.25rem', 'rem')})
        self.assertTrue(all(x['id'] and x['source'] and x['locator'] for x in tokens))
        self.assertEqual(len(first['content']['sources']), 2)
        self.assertNotIn('semantic_name', json.dumps(first))

    def test_one_token_edit_reports_file_digest_without_changing_other_tokens(self):
        module = self.extractor()
        path = self.root / 'theme.css'
        path.write_text(':root { --a: 1px; --b: 2px; }')
        old = self.capture(module, ['theme.css'])
        saved = json.dumps(old, sort_keys=True)
        path.write_text('\n:root { --a: 3px;\n --b: 2px; }')
        new = self.capture(module, ['theme.css'])
        diff = module.diff(old, new)
        self.assertEqual(len(diff['changed']), 1)
        self.assertEqual(diff['added'], [])
        self.assertEqual(diff['removed'], [])
        self.assertEqual(diff['sources_changed'], ['theme.css'])
        self.assertEqual(json.dumps(old, sort_keys=True), saved)
        self.assertEqual({x['id'] for x in old['content']['tokens']},
                         {x['id'] for x in new['content']['tokens']})

    def test_malformed_ambiguous_nonfinite_and_unsupported_never_complete(self):
        module = self.extractor()
        for text in ('{"x":1,"x":2}', '{"x":NaN}', '{bad'):
            (self.root / 'tokens.json').write_text(text)
            with self.assertRaises(module.ReferenceError):
                self.capture(module, ['tokens.json'])
        for text in (':root { --x: 1px;', ':root { --x: 1px; --x: 2px; }'):
            (self.root / 'theme.css').write_text(text)
            with self.assertRaises(module.ReferenceError):
                self.capture(module, ['theme.css'])
        (self.root / 'theme.css').write_text('@import "never-fetch.css"; :root { --x: var(--missing); }')
        result = self.capture(module, ['theme.css'])
        self.assertEqual(result['content']['coverage']['status'], 'partial')
        self.assertIn('unsupported-css', result['content']['coverage']['reasons'])

    def test_explicit_selection_caps_and_changed_source_refuse(self):
        module = self.extractor()
        (self.root / 'tokens.json').write_text('{"x":"1px","y":"2px"}')
        (self.root / 'ignored.json').write_text('not JSON')
        self.assertEqual(len(self.capture(module, ['tokens.json'])['content']['sources']), 1)
        for files in ([], ['../tokens.json'], ['tokens.json'] * 2, ['x.json'] * 17):
            with self.assertRaises(module.ReferenceError):
                self.capture(module, files)
        for limit in ('MAX_FILE_BYTES', 'MAX_TOTAL_BYTES', 'MAX_TOKENS', 'MAX_PACK_BYTES'):
            with patch.object(module, limit, 1):
                with self.assertRaises(module.ReferenceError):
                    self.capture(module, ['tokens.json'])
        with patch.object(module.time, 'monotonic', side_effect=[0, 6, 6, 6]):
            with self.assertRaises(module.ReferenceError):
                self.capture(module, ['tokens.json'])
        original = module.ReadOnlyBoundRoot.read
        calls = []
        def changing(binding, relative, **kwargs):
            observed = original(binding, relative, **kwargs)
            calls.append(relative)
            if len(calls) == 1:
                (self.root / 'tokens.json').write_text('{"x":"2px"}')
            return observed
        with patch.object(module.ReadOnlyBoundRoot, 'read', changing):
            with self.assertRaises(module.ReferenceError):
                self.capture(module, ['tokens.json'])

    def test_pack_validation_rejects_unknown_keys_digest_changes_and_duplicate_ids(self):
        module = self.extractor()
        (self.root / 'tokens.json').write_text('{"x":"1px"}')
        result = self.capture(module, ['tokens.json'])
        for mutate in (lambda x: x.update(private='x'),
                       lambda x: x.update(content_digest='0' * 64),
                       lambda x: x['content']['tokens'].append(x['content']['tokens'][0])):
            changed = json.loads(json.dumps(result))
            mutate(changed)
            with self.assertRaises(module.ReferenceError):
                module.validate_pack(changed)

    def test_disabled_cli_does_not_load_addon_or_start_processes(self):
        path = ROOT / 'scripts/getzilla_design_reference.py'
        self.assertTrue(path.is_file(), 'local design-reference command is missing')
        command = load_file(path, 'public_design_reference_cli')
        loaded = []
        def forbidden_load(*args):
            loaded.append('addon')
            raise ValueError('owned load observation')
        with patch.object(command, 'admit_module', return_value={'allowed': False}), \
                patch.object(command, '_task', return_value=None), \
                patch.object(command, '_load', side_effect=forbidden_load), \
                patch('subprocess.Popen', side_effect=AssertionError('worker started')), \
                patch('socket.create_connection', side_effect=AssertionError('network started')):
            with self.assertRaises(command.DesignReferenceError):
                command.capture(self.root, ['tokens.json'], capture_id='capture-a',
                                captured_at='2026-11-07T00:00:00Z')
        self.assertEqual(loaded, [])

    def test_css_context_quoted_punctuation_and_json_schema_agree(self):
        module = self.extractor()
        (self.root / 'theme.css').write_text('@media (min-width: 3px) { :root {\n --text: "a;/*literal*/b";\n --gap: 2px; }}')
        result = self.capture(module, ['theme.css'])
        rows = {row['name']: row for row in result['content']['tokens']}
        self.assertEqual(rows['--text']['raw_value'], '"a;/*literal*/b"')
        self.assertEqual(rows['--gap']['context'], ['@media (min-width: 3px)', ':root'])
        self.assertEqual(rows['--gap']['locator']['line'], 3)
        import jsonschema
        schema = json.loads((ROOT / '.getzilla/optional-modules/design-reference/0.1.0/pack-v1.schema.json').read_text())
        jsonschema.Draft202012Validator(schema).validate(result)

    def test_actual_owned_task_evidence_replay_diff_capacity_and_missing_owner(self):
        from getzilla.change import start_change
        from getzilla.continuity import ack_scope, submit
        from getzilla.optional_modules import manage_modules
        from getzilla.spec import canonical_spec_digest
        from getzilla.state import bind_session, current_session
        from tests.test_optional_modules import OptionalModuleTests
        previous_session = current_session()
        session = previous_session or 'public-design-fixture-session'
        bind_session(session)
        self.addCleanup(bind_session, previous_session)
        OptionalModuleTests.install_core(self, self.root)
        manage_modules(self.root, 'install', {'design-reference': '0.1.0'}, source=ROOT)
        manage_modules(self.root, 'enable', {'design-reference': None}, grants=['design.reference.read'])
        command = load_file(ROOT / 'scripts/getzilla_design_reference.py', 'public_design_reference_cli')
        (self.root / 'tokens.json').write_text('{"x":"1px","y":"2px"}')
        with self.assertRaises(command.DesignReferenceError):
            command.capture(self.root, ['tokens.json'], capture_id='a', captured_at='2026-11-07T00:00:00Z')
        self.assertFalse(list((self.root / '.getzilla/runtime').glob('changes/*/evidence/design-reference/*.json')))
        subprocess.run(['git', 'init', '--quiet', str(self.root)], check=True,
                       capture_output=True, timeout=10)
        route = submit(self.root, 'Observe this owned public token fixture only.', session, new_task=True)
        shutil.copytree(ROOT / '.getzilla/templates/change', self.root / '.getzilla/templates/change')
        (self.root / 'schemas').mkdir()
        for name in ('change-spec.schema.json', 'change-spec-v1.schema.json'):
            shutil.copyfile(ROOT / 'schemas' / name, self.root / 'schemas' / name)
        (self.root / 'tests').mkdir()
        shutil.copyfile(Path(__file__), self.root / 'tests/test_design_reference.py')
        package = start_change(self.root, 'Public design-reference fixture')
        directory = self.root / '.getzilla/runtime/changes' / package['change_id']
        spec = json.loads((directory / 'change-spec.yaml').read_text())
        spec['objective'] = {'id': 'OBJ-001', 'statement': 'Observe owned public local fixture values.',
                             'success_metric': 'Advisory immutable record only.', 'target': 'tokens.json'}
        spec['acceptance_criteria'] = [{'id': 'AC-001', 'statement': 'Retain immutable advisory public observations.',
                                        'evidence': [{'test': 'tests/test_design_reference.py'}]}]
        (directory / 'change-spec.yaml').write_text(json.dumps(spec))
        requirements = b'Observe owned public local fixture values only; no acceptance authority.\n'
        (directory / 'requirements.md').write_bytes(requirements)
        ack_scope(self.root, {'version': 1, 'operation_id': 'public-fixture-scope',
                             'route_id': route['route_id'], 'logical_task_id': route['logical_task_id'],
                             'authority_epoch': route['authority_epoch'], 'revision': 0,
                             'spec_digest': canonical_spec_digest(spec),
                             'requirements_digest': hashlib.sha256(requirements).hexdigest(),
                             'items': {'original': ['OBJ-001', 'AC-001']}})
        first = command.capture(self.root, ['tokens.json'], capture_id='a', captured_at='2026-11-07T00:00:00Z')
        old = (self.root / first['artifact']).read_bytes()
        replay = command.capture(self.root, ['tokens.json'], capture_id='a', captured_at='2026-11-07T00:00:00Z')
        self.assertEqual(first['artifact'], replay['artifact'])
        self.assertTrue(replay['replayed'])
        self.assertTrue(first['advisory'])
        self.assertEqual(json.loads(old)['task']['logical_task_id'], route['logical_task_id'])
        (self.root / 'tokens.json').write_text('{"x":"3px","y":"2px"}')
        second = command.capture(self.root, ['tokens.json'], capture_id='b', captured_at='2026-11-07T00:00:00Z')
        difference = command.compare(self.root, first['sha256'], second['sha256'])
        self.assertEqual(len(difference['changed']), 1)
        self.assertEqual(difference['sources_changed'], ['tokens.json'])
        with patch.object(command, 'MAX_HISTORY', 2):
            with self.assertRaises(command.DesignReferenceError):
                command.capture(self.root, ['tokens.json'], capture_id='c', captured_at='2026-11-07T00:00:00Z')
        self.assertEqual(len(list((directory / 'evidence/design-reference').iterdir())), 2)
        self.assertEqual((self.root / first['artifact']).read_bytes(), old)
        (self.root / 'tokens.json').write_text('{"x":"1px","y":"2px"}')
        (self.root / first['artifact']).write_bytes(b'foreign bytes retained')
        with self.assertRaises(command.DesignReferenceError):
            command.capture(self.root, ['tokens.json'], capture_id='a', captured_at='2026-11-07T00:00:00Z')
        self.assertEqual((self.root / first['artifact']).read_bytes(), b'foreign bytes retained')


if __name__ == '__main__':
    unittest.main()
