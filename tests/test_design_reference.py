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


def create_public_task(root, session):
    """Use normal task/package/scope APIs on an owned public fixture only."""
    from getzilla.change import start_change
    from getzilla.continuity import ack_scope, submit
    from getzilla.spec import canonical_spec_digest
    subprocess.run(['git', 'init', '--quiet', str(root)], check=True,
                   capture_output=True, timeout=10)
    route = submit(root, 'Observe this owned public token fixture only.', session, new_task=True)
    shutil.copytree(ROOT / '.getzilla/templates/change', root / '.getzilla/templates/change', dirs_exist_ok=True)
    (root / 'schemas').mkdir(exist_ok=True)
    for name in ('change-spec.schema.json', 'change-spec-v1.schema.json'):
        shutil.copyfile(ROOT / 'schemas' / name, root / 'schemas' / name)
    (root / 'tests').mkdir(exist_ok=True)
    shutil.copyfile(Path(__file__), root / 'tests/test_design_reference.py')
    package = start_change(root, 'Public design-reference fixture')
    directory = root / '.getzilla/runtime/changes' / package['change_id']
    spec = json.loads((directory / 'change-spec.yaml').read_text())
    spec['objective'] = {'id': 'OBJ-001', 'statement': 'Observe owned public local fixture values.',
                         'success_metric': 'Advisory immutable record only.', 'target': 'tokens.json'}
    spec['acceptance_criteria'] = [{'id': 'AC-001', 'statement': 'Retain immutable advisory public observations.',
                                    'evidence': [{'test': 'tests/test_design_reference.py'}]}]
    (directory / 'change-spec.yaml').write_text(json.dumps(spec))
    requirements = b'Observe owned public local fixture values only; no acceptance authority.\n'
    (directory / 'requirements.md').write_bytes(requirements)
    ack_scope(root, {'version': 1, 'operation_id': 'public-fixture-scope',
                    'route_id': route['route_id'], 'logical_task_id': route['logical_task_id'],
                    'authority_epoch': route['authority_epoch'], 'revision': 0,
                    'spec_digest': canonical_spec_digest(spec),
                    'requirements_digest': hashlib.sha256(requirements).hexdigest(),
                    'items': {'original': ['OBJ-001', 'AC-001']}})
    return route, directory


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

    def record_fixture(self):
        from getzilla.optional_modules import manage_modules
        from getzilla.state import bind_session, current_session
        from tests.test_optional_modules import OptionalModuleTests
        previous = current_session()
        session = previous or 'public-design-fixture-session'
        bind_session(session)
        self.addCleanup(bind_session, previous)
        OptionalModuleTests.install_core(self, self.root)
        manage_modules(self.root, 'install', {'design-reference': '0.1.0'}, source=ROOT)
        manage_modules(self.root, 'enable', {'design-reference': None}, grants=['design.reference.read'])
        _route, directory = create_public_task(self.root, session)
        command = load_file(ROOT / 'scripts/getzilla_design_reference.py', 'public_design_reference_cli')
        (self.root / 'tokens.json').write_text('{"x":"1px"}')
        first = command.capture(self.root, ['tokens.json'], capture_id='first', captured_at='2026-11-07T00:00:00Z')
        return command, directory / 'evidence/design-reference', first

    def test_full32_history_keeps_exact_replay_and_refuses_the_next_event(self):
        command, directory, first = self.record_fixture()
        for index in range(31):
            command.capture(self.root, ['tokens.json'], capture_id='event-' + str(index),
                            captured_at='2026-11-07T00:00:00Z')
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        self.assertEqual(len(before), 32)
        replay = command.capture(self.root, ['tokens.json'], capture_id='first', captured_at='2026-11-07T00:00:00Z')
        self.assertTrue(replay['replayed'])
        self.assertEqual(first['artifact'], replay['artifact'])
        with self.assertRaises(command.DesignReferenceError) as refused:
            command.capture(self.root, ['tokens.json'], capture_id='event-32', captured_at='2026-11-07T00:00:00Z')
        self.assertEqual(refused.exception.args, ('design_reference_capacity',))
        self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)

    def test_older_task_contexts_are_advisory_and_new_ids_use_fresh_binding(self):
        from getzilla.continuity import ack_scope, submit
        from getzilla.spec import canonical_spec_digest
        from getzilla.state import current_session
        command, directory, first = self.record_fixture()
        old = (self.root / first['artifact']).read_bytes()
        text = 'Include a second owned public observation; preserve the first advisory snapshot.'
        route = submit(self.root, text, current_session())
        package = directory.parents[1]
        requirements = (package / 'requirements.md').read_bytes() + text.encode() + b'\n'
        (package / 'requirements.md').write_bytes(requirements)
        spec = json.loads((package / 'change-spec.yaml').read_text())
        ack_scope(self.root, {'version': 1, 'operation_id': 'public-context-amendment',
                             'route_id': route['route_id'], 'logical_task_id': route['logical_task_id'],
                             'authority_epoch': route['authority_epoch'], 'revision': route['context']['revision'],
                             'spec_digest': canonical_spec_digest(spec),
                             'requirements_digest': hashlib.sha256(requirements).hexdigest(),
                             'items': {'original': ['OBJ-001', 'AC-001'],
                                       route['context']['pending'][0]['id']: ['AC-001']}})
        second = command.capture(self.root, ['tokens.json'], capture_id='new-context', captured_at='2026-11-07T00:00:00Z')
        new = json.loads((self.root / second['artifact']).read_bytes())
        self.assertGreater(new['task']['context_revision'], json.loads(old)['task']['context_revision'])
        self.assertEqual((self.root / first['artifact']).read_bytes(), old)
        self.assertEqual(command.compare(self.root, first['sha256'], second['sha256'])['changed'], [])
        with self.assertRaises(command.DesignReferenceError):
            command.capture(self.root, ['tokens.json'], capture_id='first', captured_at='2026-11-07T00:00:00Z')
        # Pure reader DTO contrast only: no actual handoff, principal or route change.
        context, _directory = command._task(self.root)
        later_epoch = dict(context, authority_epoch=1, context_revision=0)
        later_epoch['digest'] = hashlib.sha256(command._encode({key: value for key, value in later_epoch.items() if key != 'digest'})).hexdigest()
        admission = command._admitted(self.root)
        module = command._load(self.root, admission)
        with command.ReadOnlyBoundRoot(self.root) as binding:
            try:
                historical = command._history(binding, directory.relative_to(self.root).as_posix(), module,
                                              later_epoch, admission)
            except command.DesignReferenceError:
                self.fail('older epochs are historical advisory data, not current authority')
        self.assertEqual(len(historical), 2)
        self.assertEqual(command._task(self.root)[0]['authority_epoch'], 0)

    def test_unknown_malformed_duplicate_or_unowned_history_refuses_before_new_write(self):
        command, directory, first = self.record_fixture()
        original = (self.root / first['artifact']).read_bytes()
        extra = json.loads(original)
        extra['unknown'] = 'public fixture'
        extra['pack']['capture']['id'] = 'public-extra-capture'
        duplicate = json.loads(original)
        duplicate['pack']['capture']['timestamp'] = '2026-11-07T00:00:01Z'
        other_task = json.loads(original)
        other_task['task']['logical_task_id'] = 'task:public-other-record'
        other_task['pack']['capture']['id'] = 'public-other-capture'
        task = other_task['task']
        task['digest'] = hashlib.sha256(command._encode({key: value for key, value in task.items() if key != 'digest'})).hexdigest()
        future = json.loads(original)
        future['pack']['capture']['id'] = 'public-future-capture'
        future['task']['authority_epoch'] = 1
        future['task']['digest'] = hashlib.sha256(command._encode({key: value for key, value in future['task'].items() if key != 'digest'})).hexdigest()
        cases = [b'not JSON', b'{"schema_version":1,"schema_version":1}',
                 command._encode(extra), command._encode(duplicate), command._encode(other_task), command._encode(future),
                 b'x' * (command.MAX_RECORD_BYTES + 1)]
        for raw in cases:
            path = directory / (hashlib.sha256(raw).hexdigest() + '.json')
            path.write_bytes(raw)
            path.chmod(0o600)
            with self.assertRaises(command.DesignReferenceError):
                command.capture(self.root, ['tokens.json'], capture_id='second', captured_at='2026-11-07T00:00:00Z')
            self.assertEqual(len(list(directory.iterdir())), 2)
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual((self.root / first['artifact']).read_bytes(), original)
            path.unlink()  # Only this test's own injected fixture.
        unknown = directory / 'unknown.json'
        unknown.write_bytes(b'public unknown entry')
        with self.assertRaises(command.DesignReferenceError):
            command.capture(self.root, ['tokens.json'], capture_id='second', captured_at='2026-11-07T00:00:00Z')
        self.assertEqual(unknown.read_bytes(), b'public unknown entry')
        unknown.unlink()
        if not command.fsx.WINDOWS:
            target = self.root / first['artifact']
            target.chmod(0o644)
            with self.assertRaises(command.DesignReferenceError):
                command.capture(self.root, ['tokens.json'], capture_id='second', captured_at='2026-11-07T00:00:00Z')
            self.assertEqual(len(list(directory.iterdir())), 1)
            target.chmod(0o600)

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

    def test_selector_admission_keeps_ordinary_rules_and_never_completes_unqualified_headers(self):
        module = self.extractor()
        path = self.root / 'theme.css'
        ordinary = (':root', '.theme', '#app', 'html .theme > .card', ':root, .theme',
                    '[data-theme="dark"]', 'button:hover')
        for selector in ordinary:
            with self.subTest(supported=selector):
                path.write_text(selector + ' { --gap: 2px; }')
                result = self.capture(module, ['theme.css'])
                self.assertEqual(result['content']['coverage']['status'], 'complete')
                self.assertEqual(result['content']['coverage']['reasons'], [])
                self.assertEqual(result['content']['tokens'][0]['raw_value'], '2px')
        for selector in ('.', '#', '.theme >', ':root,', 'div..theme', ':is(.theme)', '& .theme'):
            with self.subTest(unqualified=selector):
                path.write_text(selector + ' { --gap: 2px; }')
                try:
                    result = self.capture(module, ['theme.css'])
                except module.ReferenceError:
                    continue
                self.assertEqual(result['content']['coverage']['status'], 'partial')
                self.assertIn('unsupported-css', result['content']['coverage']['reasons'])
        path.write_text('@media (min-width: 3px) { :root { --gap: 2px; } }')
        self.assertEqual(self.capture(module, ['theme.css'])['content']['coverage']['status'], 'complete')

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

    def test_self_consistent_passive_ownership_cannot_admit_different_addon_code(self):
        from getzilla.optional_modules import admit_module, manage_modules
        from getzilla.state import bind_session, current_session
        from tests.test_optional_modules import OptionalModuleTests
        previous = current_session()
        session = previous or 'public-design-fixture-session'
        bind_session(session)
        self.addCleanup(bind_session, previous)
        OptionalModuleTests.install_core(self, self.root)
        source = self.root / 'public-source'
        artifact = source / '.getzilla/optional-modules/design-reference/0.1.0'
        artifact.mkdir(parents=True)
        for name in ('module.json', 'reference.py', 'pack-v1.schema.json', 'LICENSE'):
            shutil.copyfile(ROOT / '.getzilla/optional-modules/design-reference/0.1.0' / name, artifact / name)
        reference = artifact / 'reference.py'
        reference.write_bytes(reference.read_bytes() + b'\n# different inert public artifact\n')
        descriptor = json.loads((artifact / 'module.json').read_text())
        for entry in descriptor['files']:
            if entry['path'] == 'reference.py':
                entry['sha256'] = hashlib.sha256(reference.read_bytes()).hexdigest()
        (artifact / 'module.json').write_text(json.dumps(descriptor))
        registry = json.loads((ROOT / '.getzilla/config/optional-modules.json').read_text())
        registry['modules']['design-reference']['versions']['0.1.0']['sha256'] = hashlib.sha256(
            (artifact / 'module.json').read_bytes()).hexdigest()
        (source / '.getzilla/config').mkdir()
        (source / '.getzilla/config/optional-modules.json').write_text(json.dumps(registry))
        manage_modules(self.root, 'install', {'design-reference': '0.1.0'}, source=source)
        manage_modules(self.root, 'enable', {'design-reference': None}, grants=['design.reference.read'])
        self.assertTrue(admit_module(self.root, 'design-reference', permission='design.reference.read')['allowed'])
        create_public_task(self.root, session)
        (self.root / 'tokens.json').write_text('{"x":"1px"}')
        command = load_file(ROOT / 'scripts/getzilla_design_reference.py', 'public_design_reference_cli')
        with self.assertRaises(command.DesignReferenceError):
            command.capture(self.root, ['tokens.json'], capture_id='foreign', captured_at='2026-11-07T00:00:00Z')
        self.assertFalse(list((self.root / '.getzilla/runtime').glob('changes/*/evidence/design-reference/*.json')))

    def test_actual_owned_task_evidence_replay_diff_capacity_and_missing_owner(self):
        from getzilla.optional_modules import manage_modules
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
        route, directory = create_public_task(self.root, session)
        first = command.capture(self.root, ['tokens.json'], capture_id='a', captured_at='2026-11-07T00:00:00Z')
        old = (self.root / first['artifact']).read_bytes()
        with patch.object(command, 'MAX_HISTORY', 1):
            replay = command.capture(self.root, ['tokens.json'], capture_id='a', captured_at='2026-11-07T00:00:00Z')
        self.assertEqual(first['artifact'], replay['artifact'])
        self.assertTrue(replay['replayed'])
        self.assertTrue(first['advisory'])
        self.assertEqual(json.loads(old)['task']['logical_task_id'], route['logical_task_id'])
        with self.assertRaises(command.DesignReferenceError) as refused:
            command.capture(self.root, ['tokens.json'], capture_id='a', captured_at='2026-11-07T00:00:01Z')
        self.assertEqual(refused.exception.args, ('design_reference_id_conflict',))
        self.assertEqual(len(list((directory / 'evidence/design-reference').iterdir())), 1)
        (self.root / 'tokens.json').write_text('{"x":"3px","y":"2px"}')
        with self.assertRaises(command.DesignReferenceError):
            command.capture(self.root, ['tokens.json'], capture_id='a', captured_at='2026-11-07T00:00:00Z')
        self.assertEqual(len(list((directory / 'evidence/design-reference').iterdir())), 1)
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
