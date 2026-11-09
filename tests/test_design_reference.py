"""Explicit public local fixtures for the optional design-reference child."""
from __future__ import annotations

import importlib.util
from contextlib import contextmanager
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))


def load_file(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ACCEPTED_DESIGN_BASE = '7dbeb45af030fab67bd49cf2261cf288d1ceeb7c'
DESIGN_FILES = {
    '0.1.0': ('module.json','reference.py','pack-v1.schema.json','LICENSE'),
    '0.2.0': ('module.json','reference.py','preview.py','pack-v1.schema.json','pack-v2.schema.json','LICENSE'),
}


def sealed_design_source(destination, versions):
    """Only named public artifacts; never load the repository's default catalogue."""
    destination.mkdir(mode=0o700)
    catalogue = {'schema_version':1,'core_api':1,
                 'publishers':{'getzilla':{'licenses':['MIT']}},
                 'modules':{'design-reference':{'publisher':'getzilla','versions':{}}}}
    for version in versions:
        if version not in DESIGN_FILES:
            raise ValueError('public_design_fixture_version')
        relative = '.getzilla/optional-modules/design-reference/' + version + '/'
        target = destination / relative
        target.mkdir(parents=True)
        for name in DESIGN_FILES[version]:
            raw = (subprocess.check_output(['git','show',ACCEPTED_DESIGN_BASE + ':' + relative + name],
                                           cwd=ROOT, timeout=10) if version == '0.1.0'
                   else (ROOT / relative / name).read_bytes())
            (target / name).write_bytes(raw)
        catalogue['modules']['design-reference']['versions'][version] = {
            'manifest':relative + 'module.json',
            'sha256':hashlib.sha256((target / 'module.json').read_bytes()).hexdigest()}
    folder = destination / '.getzilla/config'
    folder.mkdir(parents=True)
    (folder / 'optional-modules.json').write_text(json.dumps(catalogue))
    return destination


@contextmanager
def browser_fixture_temp(worker_script):
    """Explicit test capability; only the exact optional worker gets this temp root."""
    def need(condition):
        if not condition:
            raise ValueError('browser_fixture_temp_unavailable')
    selected = os.environ.get('GETZILLA_DESIGN_BROWSER_TEMP_ROOT', '')
    need(bool(selected) and os.name == 'posix' and hasattr(os, 'O_NOFOLLOW')
         and shutil.rmtree.avoids_symlink_attacks)
    common = subprocess.check_output(['git', 'rev-parse', '--path-format=absolute', '--git-common-dir'],
                                     cwd=ROOT, text=True, timeout=5).strip()
    runtime = Path(common).parent / '.getzilla/runtime'
    root = Path(selected)
    need(root.is_absolute() and root.parent == runtime and len(os.fsencode(root)) <= 48)
    held = []
    child = None
    child_fd = None
    def identity(info):
        return info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)
    def check():
        for parent, name, descriptor in held[1:]:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISDIR(current.st_mode) and identity(current) == identity(os.fstat(descriptor)))
        if child_fd is not None:
            current = os.stat(child, dir_fd=held[-1][2], follow_symlinks=False)
            need(stat.S_ISDIR(current.st_mode) and identity(current) == identity(os.fstat(child_fd)))
    try:
        descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        held.append((None, '/', descriptor))
        for name in root.parts[1:]:
            parent = held[-1][2]
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            held.append((parent, name, descriptor))
        info = os.fstat(descriptor)
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
        check()
        for _ in range(8):
            candidate = secrets.token_hex(3)
            try:
                os.mkdir(candidate, 0o700, dir_fd=descriptor)
                child = candidate
                break
            except FileExistsError:
                pass
        need(child is not None)
        child_fd = os.open(child, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
        child_info = os.fstat(child_fd)
        need(child_info.st_uid == os.geteuid() and stat.S_IMODE(child_info.st_mode) == 0o700)
        check()
        native_popen = subprocess.Popen
        expected = [sys.executable, '-I', '-c', worker_script]
        def launch(command, *args, **kwargs):
            if command == expected:
                check()
                environment = dict(os.environ if kwargs.get('env') is None else kwargs['env'])
                environment.update({name: str(root / child) for name in ('TMPDIR','TEMP','TMP')})
                kwargs['env'] = environment
            return native_popen(command, *args, **kwargs)
        with patch.object(subprocess, 'Popen', side_effect=launch):
            yield
        check()
    finally:
        try:
            if child is not None and child_fd is not None:
                check()
                shutil.rmtree(child, dir_fd=held[-1][2])
        finally:
            if child_fd is not None:
                os.close(child_fd)
            for _parent, _name, descriptor in reversed(held):
                os.close(descriptor)


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
        path = ROOT / '.getzilla/optional-modules/design-reference/0.2.0/reference.py'
        self.assertTrue(path.is_file(), 'explicit local design-reference artifact is missing')
        return load_file(path, 'public_design_reference')

    def test_accepted_v010_is_exact_and_v020_is_a_distinct_immutable_bundle(self):
        base = '7dbeb45af030fab67bd49cf2261cf288d1ceeb7c'
        old = ROOT / '.getzilla/optional-modules/design-reference/0.1.0'
        for name in ('module.json','reference.py','pack-v1.schema.json','LICENSE'):
            expected = subprocess.check_output(['git','show',base + ':' +
                '.getzilla/optional-modules/design-reference/0.1.0/' + name], cwd=ROOT, timeout=10)
            self.assertTrue((old / name).read_bytes() == expected,
                            'accepted immutable0.1.0 artifact changed: ' + name)
        self.assertEqual({p.name for p in old.iterdir() if p.is_file()},
                         {'module.json','reference.py','pack-v1.schema.json','LICENSE'})
        new = ROOT / '.getzilla/optional-modules/design-reference/0.2.0'
        self.assertTrue((new / 'module.json').is_file(), 'new immutable0.2.0 bundle missing')
        self.assertEqual(json.loads((new / 'module.json').read_bytes())['version'], '0.2.0')
        self.assertEqual((old / 'pack-v1.schema.json').read_bytes(), (new / 'pack-v1.schema.json').read_bytes())

    def test_architecture_declares_only_the_exact_local_reference_source(self):
        from getzilla import architecture
        snapshot = architecture.load_architecture(ROOT)
        source = '.getzilla/optional-modules/design-reference/0.2.0/reference.py'
        unrelated = '.getzilla/optional-modules/unregistered/0.1.0/reference.py'
        inventory = (architecture._RepositoryArtifact(source, 'file', (ROOT / source).stat().st_size),
                     architecture._RepositoryArtifact(unrelated, 'file', 0))
        with patch.object(architecture, '_bounded_repository_inventory', return_value=inventory):
            findings = architecture.validate_repository_drift(ROOT, snapshot)
        self.assertEqual([(item.code, item.path) for item in findings],
                         [('undeclared_source', unrelated)])
        owners = [node['id'] for node in snapshot.system['nodes'] if source in node['repository_paths']]
        self.assertEqual(owners, ['NODE-LOCAL-ROUTE-POLICY'])

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
        manage_modules(self.root, 'install', {'design-reference': '0.2.0'},
                       source=sealed_design_source(self.root / 'sealed-v020-source', ('0.2.0',)))
        manage_modules(self.root, 'enable', {'design-reference': None}, grants=['design.reference.read'])
        _route, directory = create_public_task(self.root, session)
        command = load_file(ROOT / 'scripts/getzilla_design_reference.py', 'public_design_reference_cli')
        (self.root / 'tokens.json').write_text('{"x":"1px"}')
        first = command.capture(self.root, ['tokens.json'], capture_id='first', captured_at='2026-11-07T00:00:00Z')
        return command, directory / 'evidence/design-reference', first

    def test_real_public_v010_to_v020_upgrade_preserves_history(self):
        from getzilla.optional_modules import admit_module, manage_modules
        from getzilla.state import bind_session, current_session
        from tests.test_optional_modules import OptionalModuleTests
        previous = current_session()
        session = previous or 'public-design-version-fixture'
        bind_session(session)
        self.addCleanup(bind_session, previous)
        OptionalModuleTests.install_core(self, self.root)  # Only this seven-line public seed helper.
        old_source = sealed_design_source(self.root / 'sealed-old-source', ('0.1.0',))
        new_source = sealed_design_source(self.root / 'sealed-new-source', ('0.1.0','0.2.0'))
        old_folder = old_source / '.getzilla/optional-modules/design-reference/0.1.0'
        old_bytes = {name:(old_folder / name).read_bytes() for name in DESIGN_FILES['0.1.0']}
        old_sha = hashlib.sha256(old_bytes['module.json']).hexdigest()
        old_script = subprocess.check_output(['git','show',ACCEPTED_DESIGN_BASE +
                                               ':scripts/getzilla_design_reference.py'], cwd=ROOT, timeout=10)
        script = old_source / 'scripts/getzilla_design_reference.py'
        script.parent.mkdir()
        script.write_bytes(old_script)
        manage_modules(self.root, 'install', {'design-reference':'0.1.0'}, source=old_source)
        manage_modules(self.root, 'enable', {'design-reference':None}, grants=['design.reference.read'])
        self.assertEqual(admit_module(self.root, 'design-reference', permission='design.reference.read')['manifest_sha256'], old_sha)
        create_public_task(self.root, session)
        (self.root / 'tokens.json').write_text('{"x":"1px"}')
        old_cli = load_file(script, 'actual_accepted_v010_design_cli')
        first = old_cli.capture(self.root, ['tokens.json'], capture_id='actual-old',
                                captured_at='2026-11-09T00:00:00Z')
        original_path = self.root / first['artifact']
        original_bytes = original_path.read_bytes()
        original_record = json.loads(original_bytes)
        self.assertEqual(original_record['module_manifest_sha256'], old_sha)
        new_cli = load_file(ROOT / 'scripts/getzilla_design_reference.py', 'new_v020_design_cli')
        self.assertEqual(new_cli._admitted(self.root)['version'], '0.1.0')
        compatible = new_cli.capture(self.root, ['tokens.json'], capture_id='still-old-compatible',
                                     captured_at='2026-11-09T00:00:01Z')
        self.assertEqual(new_cli.compare(self.root, first['sha256'], compatible['sha256'])['changed'], [])
        installed = self.root / '.getzilla/modules/design-reference'
        for name, raw in old_bytes.items():
            self.assertTrue((installed / name).read_bytes() == raw)
        foreign = installed / 'user.css'
        foreign.write_bytes(b'/* owned public fixture sentinel */')
        foreign_bytes = foreign.read_bytes()
        settings = self.root / '.mcp.json'
        settings.write_bytes(b'{"mcpServers":{}}\n')
        settings_bytes = settings.read_bytes()
        manage_modules(self.root, 'update', {'design-reference':'0.2.0'}, source=new_source)
        self.assertFalse(admit_module(self.root, 'design-reference')['allowed'])
        self.assertEqual(json.loads((installed / 'module.json').read_bytes())['version'], '0.2.0')
        self.assertEqual(original_path.read_bytes(), original_bytes)
        self.assertEqual(foreign.read_bytes(), foreign_bytes)
        self.assertEqual(settings.read_bytes(), settings_bytes)
        manage_modules(self.root, 'enable', {'design-reference':None}, grants=['design.reference.read'])
        new_admission = new_cli._admitted(self.root)
        self.assertEqual(new_admission['version'], '0.2.0')
        self.assertNotEqual(new_admission['manifest_sha256'], old_sha)
        current = new_cli.capture(self.root, ['tokens.json'], capture_id='actual-new',
                                  captured_at='2026-11-09T00:00:02Z')
        delta = new_cli.compare(self.root, first['sha256'], current['sha256'])
        self.assertEqual(delta, {'added':[],'removed':[],'changed':[],'sources_changed':[]})
        self.assertEqual(json.loads((self.root / current['artifact']).read_bytes())['pack']['content_digest'],
                         original_record['pack']['content_digest'])
        self.assertEqual(original_path.read_bytes(), original_bytes)
        for name, raw in old_bytes.items():
            self.assertTrue((old_folder / name).read_bytes() == raw)
            self.assertTrue((new_source / '.getzilla/optional-modules/design-reference/0.1.0' / name).read_bytes() == raw)
        print(json.dumps({'public306_upgrade':{'from':'0.1.0','to':'0.2.0','actual_old_record':True,
                          'old_d1_supported':True,'history_unchanged':True,'foreign_unchanged':True,
                          'old_manifest':old_sha,'new_manifest':new_admission['manifest_sha256']},
                          'lifecycle166_acceptance':False}, sort_keys=True))

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

    def test_context_admission_requires_complete_bounded_headers_in_all_four_families(self):
        module = self.extractor()
        path = self.root / 'theme.css'
        supported = ('@media screen', '@media screen and (min-width: 3px)',
                     '@media (min-width: 3px)', '@supports (display: grid)',
                     '@container card (min-width: 3px)', '@container (width: 3px)',
                     '@layer theme', '@layer theme.base')
        unqualified = ('@media screen and and', '@media nonsense',
                       '@supports nonsense', '@supports (display: grid) trailing',
                       '@container nonsense', '@container card (min-width: 3px) trailing',
                       '@layer .', '@layer theme, other',
                       '@media (min-width: 3px) or (height: 4px)',
                       '@supports selector(:root)', '@container style(--theme: dark)',
                       '@layer theme..base')
        for complete, headers in ((True, supported), (False, unqualified)):
            for header in headers:
                with self.subTest(complete=complete, header=header):
                    path.write_text(header + ' { :root { --gap: 2px; } }')
                    result = self.capture(module, ['theme.css'])['content']
                    self.assertEqual(result['tokens'][0]['raw_value'], '2px')
                    self.assertEqual(result['tokens'][0]['context'], [header, ':root'])
                    self.assertEqual(result['coverage']['status'], 'complete' if complete else 'partial')
                    self.assertEqual(result['coverage']['reasons'], [] if complete else ['unsupported-css'])

    def test_context_reserved_names_exclude_ascii_case_variants_without_normalizing_user_names(self):
        module = self.extractor()
        path = self.root / 'theme.css'
        supported = ('@layer Theme', '@layer theme.CARD', '@layer INHERITance',
                     '@container Card (width: 3px)', '@container NONEtheme (width: 3px)')
        reserved = ('initial', 'inherit', 'unset', 'revert', 'revert-layer', 'default',
                    'none', 'normal', 'and', 'or', 'not')
        unqualified = ['@layer K', '@container K (width: 3px)']
        for word in reserved:
            for variant in (word.upper(), word.title()):
                unqualified.extend(('@layer ' + variant, '@layer theme.' + variant,
                                    '@container ' + variant + ' (width: 3px)'))
        for complete, headers in ((True, supported), (False, unqualified)):
            for header in headers:
                with self.subTest(complete=complete, header=header):
                    path.write_text(header + ' { :root { --gap: 2px; } }')
                    result = self.capture(module, ['theme.css'])['content']
                    self.assertEqual(result['tokens'][0]['context'], [header, ':root'])
                    self.assertEqual(result['tokens'][0]['raw_value'], '2px')
                    self.assertEqual(result['coverage']['status'], 'complete' if complete else 'partial')
                    self.assertEqual(result['coverage']['reasons'], [] if complete else ['unsupported-css'])

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
        schema = json.loads((ROOT / '.getzilla/optional-modules/design-reference/0.2.0/pack-v1.schema.json').read_text())
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
        source = sealed_design_source(self.root / 'public-source', ('0.2.0',))
        artifact = source / '.getzilla/optional-modules/design-reference/0.2.0'
        reference = artifact / 'reference.py'
        reference.write_bytes(reference.read_bytes() + b'\n# different inert public artifact\n')
        descriptor = json.loads((artifact / 'module.json').read_text())
        for entry in descriptor['files']:
            if entry['path'] == 'reference.py':
                entry['sha256'] = hashlib.sha256(reference.read_bytes()).hexdigest()
        (artifact / 'module.json').write_text(json.dumps(descriptor))
        registry = json.loads((source / '.getzilla/config/optional-modules.json').read_text())
        registry['modules']['design-reference']['versions']['0.2.0']['sha256'] = hashlib.sha256(
            (artifact / 'module.json').read_bytes()).hexdigest()
        (source / '.getzilla/config/optional-modules.json').write_text(json.dumps(registry))
        manage_modules(self.root, 'install', {'design-reference': '0.2.0'}, source=source)
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
        manage_modules(self.root, 'install', {'design-reference': '0.2.0'},
                       source=sealed_design_source(self.root / 'sealed-v020-source', ('0.2.0',)))
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

class PreviewDesignReferenceTests(unittest.TestCase):
    def setUp(self):
        if (os.environ.get('GETZILLA_DESIGN_BROWSER_TESTS') == '1'
                and self._testMethodName.startswith(('test_controlled_preview', 'test_fixture_'))):
            adapter = load_file(ROOT / '.getzilla/optional-modules/design-reference/0.2.0/preview.py',
                                'explicit_browser_fixture_adapter')
            self.enterContext(browser_fixture_temp(adapter._PREVIEW_WORKER))

    def extractor(self):
        from functools import partial
        reference = load_file(ROOT / '.getzilla/optional-modules/design-reference/0.2.0/reference.py',
                              'preview_design_reference')
        preview = load_file(ROOT / '.getzilla/optional-modules/design-reference/0.2.0/preview.py',
                            'preview_design_adapter')
        reference.capture_preview = partial(preview.capture_preview, reference)
        return reference

    def test_preview_owned_streams_close_on_timeout_reap_error_and_setup_failure(self):
        module = self.extractor()
        for case in ('timeout-reap-timeout', 'initial-procstat-failure'):
            with self.subTest(case=case):
                process = Mock(pid=4321, returncode=-9)
                process.stdin, process.stdout = Mock(), Mock()
                process.communicate.side_effect = subprocess.TimeoutExpired('owned-worker', 15)
                process.wait.side_effect = (subprocess.TimeoutExpired('owned-worker', 2)
                                            if case == 'timeout-reap-timeout' else None)
                fields = ['S','1'] + ['0'] * 17 + ['12345']
                with patch.object(subprocess, 'Popen', return_value=process), \
                     patch('pathlib.Path') as paths, patch('threading.Thread'), \
                     patch('os.pidfd_open', return_value=90), patch('os.close'), \
                     patch('signal.pidfd_send_signal') as signal_mock:
                    paths.return_value.iterdir.return_value = []
                    if case == 'initial-procstat-failure':
                        paths.return_value.read_text.side_effect = OSError('owned fixture procstat unavailable')
                    else:
                        paths.return_value.read_text.return_value = '4321 (worker) ' + ' '.join(fields)
                    with self.assertRaises((ValueError, OSError, subprocess.TimeoutExpired)):
                        module.capture_preview('http://127.0.0.1:8000/', ['http://127.0.0.1:8000/'],
                                               capture_id='stream-unit', captured_at='2026-11-09T00:00:00Z')
                    process.stdin.close.assert_called_once_with()
                    process.stdout.close.assert_called_once_with()
                    process.wait.assert_called_once_with(timeout=2)
                    if case == 'initial-procstat-failure':
                        process.kill.assert_called_once_with()
                        signal_mock.assert_not_called()

    def test_optional_transport_has_separate_source_and_architecture_boundary(self):
        import ast
        from getzilla import architecture
        preview = '.getzilla/optional-modules/design-reference/0.2.0/preview.py'
        self.assertTrue((ROOT / preview).is_file(), 'separate optional preview adapter is missing')
        reference = ROOT / '.getzilla/optional-modules/design-reference/0.2.0/reference.py'
        imports = {item.name for node in ast.walk(ast.parse(reference.read_text()))
                   if isinstance(node, ast.Import) for item in node.names}
        self.assertFalse(imports & {'subprocess','http.client','playwright','socket'})
        snapshot = architecture.load_architecture(ROOT)
        owners = [node['id'] for node in snapshot.system['nodes'] if preview in node['repository_paths']]
        self.assertEqual(owners, ['NODE-OPTIONAL-DESIGN-PREVIEW'])
        policy = next(n for n in snapshot.system['nodes'] if n['id'] == 'NODE-LOCAL-ROUTE-POLICY')
        self.assertEqual(policy['runtime']['network'], 'none')

    def test_browser_fixture_temp_root_is_explicit_and_worker_only(self):
        helper = globals().get('browser_fixture_temp')
        self.assertTrue(callable(helper), 'explicit browser fixture temp capability is missing')
        for value in ('', '/tmp', '/outside-canonical-runtime'):
            with self.subTest(value=value), patch.dict(os.environ, {'GETZILLA_DESIGN_BROWSER_TEMP_ROOT': value}):
                with self.assertRaisesRegex(ValueError, 'browser_fixture_temp_unavailable'):
                    with helper('controlled-worker'):
                        pass
        if os.environ.get('GETZILLA_DESIGN_BROWSER_TEMP_ROOT'):
            original = {key: os.environ.get(key) for key in ('TMPDIR','TEMP','TMP')}
            common = subprocess.check_output(['git', 'rev-parse', '--path-format=absolute', '--git-common-dir'],
                                             cwd=ROOT, text=True, timeout=5)
            with patch.object(subprocess, 'Popen') as native, \
                 patch.object(subprocess, 'check_output', return_value=common):
                with helper('controlled-worker'):
                    subprocess.Popen([sys.executable, '-I', '-c', 'controlled-worker'])
                    child = Path(native.call_args.kwargs['env']['TMPDIR'])
                    self.assertEqual(child.parent, Path(os.environ['GETZILLA_DESIGN_BROWSER_TEMP_ROOT']))
                    self.assertEqual(stat.S_IMODE(child.stat().st_mode), 0o700)
                    self.assertEqual({key: os.environ.get(key) for key in original}, original)
                    subprocess.Popen([sys.executable, '-c', 'ordinary-unlaunched-fixture'])
                    self.assertNotIn('env', native.call_args.kwargs)
                self.assertFalse(child.exists())

    def test_live_and_unbounded_scope_refused_before_browser_import(self):
        module = self.extractor()
        self.assertTrue(callable(getattr(module, 'capture_preview', None)), 'preview capture is missing')
        for url in ('https://example.com/', 'http://localhost:8000/', 'http://127.0.0.1:8000/#x'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                module.capture_preview(url, [url], capture_id='preview',
                                       captured_at='2026-11-09T00:00:00Z')

    @unittest.skipUnless(os.environ.get('GETZILLA_DESIGN_BROWSER_TESTS') == '1',
                         'explicit optional browser qualification only')
    def test_controlled_preview_blocks_mutations_and_preserves_observations(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        hits = []
        body = b'''<!doctype html><style>button { color: rgb(1, 2, 3); border-radius: 7px }</style>
<button onclick="this.style.color='rgb(9, 9, 9)';fetch('/click',{method:'POST'})">Go</button><a href='/click' onclick="document.querySelector('button').style.color='rgb(9, 9, 9)'">Link</a>
<script>fetch('/write',{method:'POST'}); navigator.sendBeacon('/beacon','x');
new WebSocket('ws://127.0.0.1:PORT/socket'); fetch('/read');
setTimeout(()=>document.body.setAttribute('data-dynamic','yes'),20);</script>'''
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                hits.append(('GET', self.path))
                value = body.replace(b'PORT', str(self.server.server_port).encode())
                self.send_response(200)
                self.send_header('Content-Length', str(len(value)))
                self.end_headers()
                self.wfile.write(value)
            def do_POST(self):
                hits.append(('POST', self.path))
                self.send_response(204)
                self.end_headers()
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def stop_server():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        self.addCleanup(stop_server)
        url = f'http://127.0.0.1:{server.server_port}/'
        module = self.extractor()
        self.assertTrue(callable(getattr(module, 'capture_preview', None)), 'preview capture is missing')
        pack = module.capture_preview(url, [url], capture_id='preview',
                                      captured_at='2026-11-09T00:00:00Z')
        self.assertEqual(hits, [('GET', '/')])
        self.assertEqual(pack['content']['coverage']['status'], 'partial')
        self.assertIn('blocked-transport', pack['content']['coverage']['reasons'])
        self.assertIn('dynamic-content', pack['content']['coverage']['reasons'])
        self.assertTrue(any(t['raw_value'] == 'rgb(1, 2, 3)' for t in pack['content']['tokens']))
        module.validate_pack(pack)
        import jsonschema
        schema = json.loads((ROOT / '.getzilla/optional-modules/design-reference/0.2.0/pack-v2.schema.json').read_text())
        jsonschema.Draft202012Validator(schema).validate(pack)
        again = module.capture_preview(url, [url], capture_id='preview2',
                                       captured_at='2026-11-09T01:00:00Z')
        self.assertEqual(pack['content_digest'], again['content_digest'])
        self.assertEqual(module.diff(pack, again)['changed'], [])
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        command, directory, local = LocalDesignReferenceTests.record_fixture(self)
        local_bytes = (self.root / local['artifact']).read_bytes()
        published = command.capture_preview(self.root, url, [url], capture_id='published-preview',
                                            captured_at='2026-11-09T00:00:00Z')
        replay = command.capture_preview(self.root, url, [url], capture_id='published-preview',
                                         captured_at='2026-11-09T00:00:00Z')
        self.assertTrue(replay['replayed'])
        self.assertEqual(published['artifact'], replay['artifact'])
        self.assertEqual((self.root / local['artifact']).read_bytes(), local_bytes)
        self.assertEqual(len(list(directory.iterdir())), 2)
        self.assertEqual(command.compare(self.root, published['sha256'], replay['sha256'])['changed'], [])
        print(json.dumps({'fixture_requests': hits, 'browser': pack['content']['browser'],
                          'affinity': sorted(os.sched_getaffinity(0)), 'immutable_history_records': 2, 'worker_interpreter': sys.executable,
                          'browser_temp_policy': 'explicit-owned-short-canonical-runtime'}, sort_keys=True))
        pack['content']['parameters']['theme'] = 'invalid'
        with self.assertRaises(ValueError):
            module.validate_pack(pack)

    def test_preview_parameters_are_closed_and_bounded(self):
        module = self.extractor()
        url = 'http://127.0.0.1:8000/'
        for resources, viewport, theme, locale in (
                ([url, 'http://127.0.0.1:8001/style'], {'width':800,'height':600}, 'light', 'en'),
                ([url], {'width':True,'height':600}, 'light', 'en'),
                ([url], {'width':800,'height':600}, 'system', 'en'),
                ([url], {'width':800,'height':600}, 'light', '../en'),
                ([url + '?q=\n'], {'width':800,'height':600}, 'light', 'en')):
            with self.subTest(resources=resources, viewport=viewport, theme=theme, locale=locale):
                with self.assertRaises(ValueError):
                    module._preview_parameters(url, resources, viewport, theme, locale)

    @unittest.skipUnless(os.environ.get('GETZILLA_DESIGN_BROWSER_TESTS') == '1',
                         'explicit optional browser qualification only')
    def test_fixture_resource_refusals_and_loading_limits(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        hits = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                hits.append(self.path)
                if self.path == '/':
                    value = (b'<link rel="stylesheet" href="/missing.css">'
                             b'<link rel="stylesheet" href="/redirect.css">'
                             b'<link rel="stylesheet" href="/large.css">'
                             b'<img src="http://127.0.0.1:1/outside">'
                             b'<img src="/denied">' + b'<div>x</div>' * 150)
                    status = 200
                elif self.path == '/redirect.css':
                    self.send_response(302)
                    self.send_header('Location', '/mutation')
                    self.end_headers()
                    return
                elif self.path == '/large.css':
                    value, status = b'x' * 262145, 200
                else:
                    value, status = b'', 404
                self.send_response(status)
                self.send_header('Content-Length', str(len(value)))
                self.end_headers()
                self.wfile.write(value)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def stop_server():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        self.addCleanup(stop_server)
        url = f'http://127.0.0.1:{server.server_port}/'
        resources = sorted([url, url + 'missing.css', url + 'redirect.css', url + 'large.css'])
        module = self.extractor()
        pack = module.capture_preview(url, resources, capture_id='limited',
                                      captured_at='2026-11-09T00:00:00Z')
        reasons = pack['content']['coverage']['reasons']
        self.assertTrue({'blocked-transport','resource-unavailable','response-budget',
                         'dom-budget','loading-incomplete'} <= set(reasons), reasons)
        self.assertNotIn('/denied', hits)
        self.assertNotIn('/mutation', hits)
        self.assertEqual(len(pack['content']['tokens']), 1536)

    def test_disabled_preview_never_loads_adapter(self):
        command = load_file(ROOT / 'scripts/getzilla_design_reference.py', 'preview_command')
        with patch.object(command, '_admitted', side_effect=command.DesignReferenceError('disabled')), \
             patch.object(command, '_load') as load:
            with self.assertRaises(command.DesignReferenceError):
                command.capture_preview(ROOT, 'http://127.0.0.1:8000/', [],
                                        capture_id='disabled', captured_at='2026-11-09T00:00:00Z')
            load.assert_not_called()

    @unittest.skipUnless(os.environ.get('GETZILLA_DESIGN_BROWSER_TESTS') == '1',
                         'explicit optional browser qualification only')
    def test_fixture_font_failure_and_single_property_diff(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        version = [3]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                if self.path == '/font':
                    self.send_response(404)
                    self.end_headers()
                    return
                value = ("<style>@font-face{font-family:Missing;src:url('/font')}"
                         "button{font-family:Missing;color:rgb(1,2," + str(version[0])
                         + ")}</style><button>x</button>").encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(value)))
                self.end_headers()
                self.wfile.write(value)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f'http://127.0.0.1:{server.server_port}/'
        module = self.extractor()
        packs = []
        for index in (3,4):
            version[0] = index
            packs.append(module.capture_preview(url, [url, url + 'font'], capture_id='font' + str(index),
                                                captured_at='2026-11-09T00:00:00Z'))
        self.assertIn('fonts-incomplete', packs[0]['content']['coverage']['reasons'])
        delta = module.diff(*packs)
        self.assertEqual(len(delta['changed']), 1)
        self.assertEqual(delta['sources_changed'], [url])
        self.assertFalse(delta['added'] or delta['removed'])

    @unittest.skipUnless(os.environ.get('GETZILLA_DESIGN_BROWSER_TESTS') == '1',
                         'explicit optional browser qualification only')
    def test_fixture_infinite_script_hits_hard_deadline_and_stops_worker_group(self):
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                value = b'<script>setTimeout(()=>{while(true){}},50)</script>'
                self.send_response(200)
                self.send_header('Content-Length', str(len(value)))
                self.end_headers()
                self.wfile.write(value)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        url = f'http://127.0.0.1:{server.server_port}/'
        module = self.extractor()
        spawned = []
        observed = {}
        finished = threading.Event()
        def process_rows():
            rows = {}
            for entry in list(Path('/proc').iterdir())[:8192]:
                if entry.name.isdigit():
                    try:
                        fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
                        rows[int(entry.name)] = (int(fields[1]), fields[0], fields[19])
                    except (FileNotFoundError, ProcessLookupError, PermissionError):
                        pass
            return rows
        def monitor():
            while not finished.wait(.05):
                rows = process_rows()
                family = {spawned[0].pid}
                for _ in range(16):
                    family.update(pid for pid, row in rows.items() if row[0] in family)
                observed.update({pid:rows[pid][2] for pid in family if pid in rows})
        real = subprocess.Popen
        def observe(*args, **kwargs):
            proc = real(*args, **kwargs)
            spawned.append(proc)
            threading.Thread(target=monitor, daemon=True).start()
            return proc
        started = time.monotonic()
        with patch.object(subprocess, 'Popen', side_effect=observe):
            with self.assertRaisesRegex(module.ReferenceError, 'preview_timeout'):
                module.capture_preview(url, [url], capture_id='timeout',
                                       captured_at='2026-11-09T00:00:00Z')
        finished.set()
        self.assertLess(time.monotonic() - started, 20)
        self.assertIsNotNone(spawned[0].poll())
        self.assertGreater(len(observed), 2, 'browser descendants were not observed')
        remaining = process_rows()
        for pid, birth in observed.items():
            if pid in remaining and remaining[pid][2] == birth:
                self.assertEqual(remaining[pid][1], 'Z', 'observed browser descendant survived')
        # Child zombies may await PID1 reaping; no running group member may remain.
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():
                continue
            try:
                status = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            if int(status[2]) == spawned[0].pid:
                self.assertEqual(status[0], 'Z', 'running browser descendant survived deadline')
        print(json.dumps({'preview_deadline_seconds': round(time.monotonic() - started, 2),
                          'worker_reaped': True, 'observed_family_pids': len(observed), 'running_observed_descendants': 0,
                          'running_group_members': 0}))
