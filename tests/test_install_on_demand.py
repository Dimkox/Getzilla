"""F01 and F03: the plan shows each component's size; a project gets core plus its agent, the rest on demand."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
import errno
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.on_demand import MANIFEST, ensure_components, is_installed_project, load_manifest  # noqa: E402

SPEC = importlib.util.spec_from_file_location('install_into_on_demand_test', ROOT / 'scripts' / 'install_into.py')
INSTALL = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INSTALL
SPEC.loader.exec_module(INSTALL)


def plan(target: Path, *args: str, environment: dict[str, str] | None = None) -> dict:
    env = ({key: value for key, value in os.environ.items() if key != 'GETZILLA_AGENT'}
           if environment is None else environment)
    result = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'install_into.py'), '--plan', str(target), *args],
                            capture_output=True, text=True, check=True, env=env)
    return json.loads(result.stdout)


class ComponentStateRegressionTests(unittest.TestCase):
    def test_explicit_empty_agents_is_not_replaced_by_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'project'
            with mock.patch.dict(os.environ, {'GETZILLA_AGENT': 'codex'}):
                report = plan(target, '--agents', '', environment=dict(os.environ))
            self.assertEqual(report['selection']['agents'], [])
            paths = {entry['path'] for entry in report['entries']}
            self.assertFalse(any(INSTALL.component_of(path).startswith('agent:') for path in paths))

    def test_full_layout_and_explicit_agents_are_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(ROOT / 'scripts/install_into.py'), '--plan',
                 str(Path(tmp) / 'project'), '--full-layout', '--agents', ''],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 2)
        self.assertIn('--agents', result.stderr)

    def test_invalid_manifest_is_not_an_empty_legacy_state(self) -> None:
        invalid = [
            b'{', b'[]', b'{"schema_version":"future","components":{}}',
            b'{"schema_version":"getzilla-managed-components-v1","components":[]}',
            b'{"schema_version":"getzilla-managed-components-v2","agents":[],"agents":["qwen"],"components":{}}',
            b'{"schema_version":"getzilla-managed-components-v2","agents":["qwen","qwen"],"components":{}}',
            b'{"schema_version":"getzilla-managed-components-v2","agents":["unknown"],"components":{}}',
            b'{"schema_version":"getzilla-managed-components-v2","agents":[],"components":{"agent:qwen":{"files":["../outside"]}}}',
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / MANIFEST
            path.parent.mkdir()
            for content in invalid:
                with self.subTest(content=content):
                    path.write_bytes(content)
                    with self.assertRaises(ValueError):
                        load_manifest(root)
                    self.assertEqual(path.read_bytes(), content)

    @unittest.skipUnless(hasattr(os, 'symlink'), 'symlinks unavailable')
    def test_manifest_symlink_is_refused_without_reading_its_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'project'
            (root / '.getzilla').mkdir(parents=True)
            outside = Path(tmp) / 'outside.json'
            content = b'{"schema_version":"getzilla-managed-components-v1","components":{}}'
            outside.write_bytes(content)
            try:
                (root / MANIFEST).symlink_to(outside)
            except OSError as exc:
                self.skipTest(str(exc))
            with self.assertRaises(ValueError):
                load_manifest(root)
            self.assertEqual(outside.read_bytes(), content)

    def test_case_aliases_cannot_own_protected_or_duplicate_paths(self) -> None:
        from getzilla.component_state import decode_manifest, V2
        for files in (['.GIT/config'], ['.Getzilla/Managed-Components.json'],
                      ['.GETZILLA/runtime/private.json'], ['README.md', 'readme.md']):
            with self.subTest(files=files):
                data = {'schema_version': V2, 'agents': [], 'components': {'core': {'files': files}}}
                with self.assertRaises(ValueError):
                    decode_manifest(json.dumps(data).encode())


class ComponentTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / 'project'
        (self.root / '.getzilla').mkdir(parents=True)

    def test_absent_legacy_and_selected_empty_are_distinct(self) -> None:
        from getzilla.component_state import read_state, V1, V2
        self.assertEqual(read_state(self.root).kind, 'absent')
        path = self.root / MANIFEST
        path.write_text(json.dumps({'schema_version': V1, 'components': {}}))
        self.assertEqual(read_state(self.root).kind, 'legacy')
        with self.assertRaisesRegex(ValueError, 'adopt'):
            read_state(self.root).require_selection()
        path.write_text(json.dumps({'schema_version': V2, 'agents': [], 'components': {}}))
        self.assertEqual(read_state(self.root).require_selection(), ())

    def test_bounded_lock_contention_and_persistent_guard(self) -> None:
        from getzilla.component_state import component_transaction
        with component_transaction(self.root):
            with self.assertRaisesRegex(ValueError, 'busy'):
                with component_transaction(self.root, timeout=0):
                    self.fail('second writer acquired the guard')
        guard = self.root / '.getzilla/runtime/.components.guard.lock'
        before = guard.stat()
        with component_transaction(self.root, timeout=0):
            pass
        self.assertEqual(guard.stat().st_ino, before.st_ino)
        self.assertEqual(guard.read_bytes(), b'')

    def test_contended_lock_does_not_acquire_after_its_deadline(self) -> None:
        from getzilla import component_state, fsx
        now = [0.0]
        clock = mock.Mock()
        clock.monotonic.side_effect = lambda: now[0]
        clock.sleep.side_effect = lambda interval: now.__setitem__(0, now[0] + interval + 0.1)
        with mock.patch.object(component_state, 'time', clock), \
                mock.patch.object(fsx, 'lock_file', side_effect=[BlockingIOError(errno.EAGAIN, 'busy'), None]) as acquire, \
                mock.patch.object(fsx, 'unlock_file'):
            with self.assertRaisesRegex(ValueError, 'busy'):
                with component_state.component_transaction(self.root, timeout=0.05):
                    self.fail('expired writer entered the protected section')
            self.assertEqual(acquire.call_count, 1)

    def test_source_inventory_limit_stops_iteration_before_collecting_every_entry(self) -> None:
        from getzilla import component_state, fsx
        directory = self.root / 'inputs'
        directory.mkdir()
        for index in range(6):
            (directory / f'{index}.txt').write_text('input')
        real = fsx.scandir
        visited = []
        @contextmanager
        def counted(handle):
            with real(handle) as listing:
                def entries():
                    for entry in listing:
                        visited.append(entry.name)
                        yield entry
                yield entries()
        with mock.patch.object(component_state, 'MAX_FILES', 2), mock.patch.object(fsx, 'scandir', counted):
            with component_state.BoundRoot(self.root) as binding:
                with self.assertRaisesRegex(ValueError, 'limit'):
                    binding.files('inputs', recursive=True)
        self.assertLessEqual(len(visited), 3)

    def test_disappearing_source_child_is_not_reported_as_an_empty_inventory(self) -> None:
        from getzilla import component_state, fsx
        directory = self.root / 'inputs'
        directory.mkdir()
        missing = directory / 'a.txt'
        missing.write_text('input')
        retained = directory / 'b.txt'
        retained.write_text('retained')
        original = fsx.lstat_at
        def disappear(parent, name):
            if name == 'a.txt' and missing.exists():
                missing.unlink()
            return original(parent, name)
        with component_state.BoundRoot(self.root) as binding, mock.patch.object(fsx, 'lstat_at', disappear):
            with self.assertRaisesRegex(ValueError, 'disappeared'):
                binding.files('inputs', recursive=True)
        self.assertEqual(retained.read_text(), 'retained')

    def test_cooperating_writers_preserve_both_additions(self) -> None:
        from getzilla.component_state import component_transaction, encode_manifest, read_state, V2
        (self.root / MANIFEST).write_bytes(encode_manifest({'schema_version': V2, 'agents': [], 'components': {}}))
        def add(name: str) -> None:
            with component_transaction(self.root) as transaction:
                state = read_state(self.root, binding=transaction)
                state.manifest['agents'] = [*state.require_selection(), name]
                transaction.write(MANIFEST, encode_manifest(state.manifest), 0o644,
                                  expected=transaction.read(MANIFEST))
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(add, ('qwen', 'codex')))
        self.assertEqual(set(read_state(self.root).require_selection()), {'qwen', 'codex'})

    def test_no_clobber_at_final_publication(self) -> None:
        from getzilla import fsx
        from getzilla.component_state import component_transaction
        original_link = fsx.link_at
        def competing_file(source_parent, source, target_parent, target):
            descriptor = fsx.open_at(target_parent, target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            try:
                os.write(descriptor, b'concurrent user file')
            finally:
                os.close(descriptor)
            return original_link(source_parent, source, target_parent, target)
        with component_transaction(self.root) as transaction:
            with mock.patch.object(fsx, 'link_at', side_effect=competing_file):
                with self.assertRaises(ValueError):
                    transaction.write('new.txt', b'managed output', 0o644, expected=None)
        self.assertEqual((self.root / 'new.txt').read_bytes(), b'concurrent user file')
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ['.getzilla', 'new.txt'])

    @unittest.skipIf(os.name == 'nt', 'POSIX hardlink and FIFO semantics')
    def test_manifest_hardlink_and_fifo_are_refused(self) -> None:
        from getzilla.component_state import read_state
        outside = self.root.parent / 'outside'
        outside.write_text('{"schema_version":"getzilla-managed-components-v1","components":{}}')
        path = self.root / MANIFEST
        os.link(outside, path)
        with self.assertRaises(ValueError):
            read_state(self.root)
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(ValueError):
            read_state(self.root)

    @unittest.skipIf(os.name == 'nt', 'POSIX allows renaming an open directory')
    def test_replaced_root_refuses_writes(self) -> None:
        from getzilla.component_state import component_transaction
        moved = self.root.with_name('moved')
        with self.assertRaises(ValueError):
            with component_transaction(self.root) as transaction:
                self.root.rename(moved)
                self.root.mkdir()
                transaction.write('new.txt', b'managed', 0o644, expected=None)
        self.assertFalse((moved / 'new.txt').exists())
        self.assertFalse((self.root / 'new.txt').exists())

    def test_windows_path_handles_retain_the_opened_directory_identity(self) -> None:
        from getzilla import fsx
        from getzilla.component_state import BoundRoot
        # Exercise the portable Windows path-handle branch on this filesystem.
        with mock.patch.object(fsx, 'WINDOWS', True):
            with BoundRoot(self.root) as binding:
                self.root.rename(self.root.with_name('moved'))
                self.root.mkdir()
                with self.assertRaises(ValueError):
                    binding.read('absent.txt')


class FreshSelectionTests(unittest.TestCase):
    def test_installed_harness_from_a_subdirectory_uses_selected_zip_engine(self) -> None:
        from getzilla.component_state import read_state
        source_manifest = (ROOT / MANIFEST).read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            for index, agents in enumerate(((), ('codex',))):
                with self.subTest(agents=agents):
                    target = Path(tmp) / str(index)
                    INSTALL._materialize_new(
                        ROOT, target, include_dependencies=False, include_optional=False,
                        selection=INSTALL.PayloadSelection(agents, engine_archive=True),
                    )
                    self.assertTrue((target / INSTALL.ENGINE_ARCHIVE).is_file())
                    self.assertFalse((target / '.getzilla/getzilla/harnesses.py').exists())
                    unselected = target / '.qwen/settings.json'
                    unselected.parent.mkdir()
                    unselected.write_text('unselected custom settings\n')
                    subdirectory = target / 'src/deep'
                    subdirectory.mkdir(parents=True)
                    custom_source = b'description = "Consumer-only agent"\ndeveloper_instructions = "Keep this project specific."\n'
                    (target / '.grok/agents/consumer_only.toml').write_bytes(custom_source)
                    generated = '.codex/agents/consumer_only.toml'
                    environment = {**os.environ, 'GETZILLA_AGENT': 'qwen'}
                    before = subprocess.run([sys.executable, '-I', str(target / 'scripts/getzilla_harness.py')],
                                            cwd=subdirectory, env=environment, text=True, capture_output=True, timeout=30)
                    self.assertEqual(before.returncode, 1 if agents else 0, before.stdout + before.stderr)
                    if agents:
                        self.assertIn(generated, before.stdout)
                    for script, arguments in (
                        (target / 'scripts/getzilla_harness.py', ['--write']),
                        (ROOT / 'scripts/getzilla_cli.py', ['harness', '--write']),
                        (target / 'scripts/getzilla_harness.py', []),
                    ):
                        result = subprocess.run([sys.executable, '-I', str(script), *arguments], cwd=subdirectory,
                                                env=environment, text=True, capture_output=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    state = read_state(target)
                    self.assertEqual(state.require_selection(), agents)
                    if agents:
                        self.assertEqual((target / generated).read_bytes(), custom_source)
                        self.assertEqual(state.manifest['components']['agent:codex']['owned'][generated]['sha256'],
                                         hashlib.sha256(custom_source).hexdigest())
                    else:
                        self.assertFalse((target / generated).exists())
                    self.assertEqual(unselected.read_text(), 'unselected custom settings\n')
                    self.assertEqual((target / '.codex/hooks.json').is_file(), 'codex' in agents)
                    self.assertFalse((target / '.claude').exists())
                    self.assertEqual((ROOT / MANIFEST).read_bytes(), source_manifest)

    def test_fresh_install_records_exact_selection_and_actual_file_ownership(self) -> None:
        from getzilla.component_state import mode_matches, read_state
        with tempfile.TemporaryDirectory() as tmp:
            for index, agents in enumerate(((), ('qwen',), INSTALL.KNOWN_AGENTS)):
                with self.subTest(agents=agents):
                    target = Path(tmp) / str(index)
                    report = INSTALL._materialize_new(
                        ROOT, target, include_dependencies=False, include_optional=False,
                        selection=INSTALL.PayloadSelection(agents),
                    )
                    state = read_state(target)
                    self.assertEqual(state.kind, 'selected')
                    self.assertEqual(state.require_selection(), agents)
                    self.assertEqual(report['selection']['agents'], list(agents))
                    records = state.manifest['components']
                    owned = {path: proof for record in records.values() for path, proof in record['owned'].items()}
                    self.assertEqual(set(owned), {entry['path'] for entry in report['entries']} - {MANIFEST})
                    for path, proof in owned.items():
                        artifact = target / path
                        self.assertEqual(proof['sha256'], hashlib.sha256(artifact.read_bytes()).hexdigest(), path)
                        self.assertTrue(mode_matches(artifact.stat().st_mode, proof['mode']), path)
                    self.assertNotIn(MANIFEST, owned)
                    self.assertNotIn('.getzilla/runtime/.components.guard.lock', owned)
                    self.assertIn('.getzilla/getzilla/__init__.py', owned)
                    self.assertEqual({INSTALL._agent_of(path) for path in owned if INSTALL._agent_of(path)}, set(agents))
                    self.assertTrue((target / 'scripts/getzilla_harness.py').is_file())

    def test_selected_manifest_overrides_environment_and_unselected_directories(self) -> None:
        from getzilla.component_state import encode_manifest, V2
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / '.getzilla').mkdir()
            (target / MANIFEST).write_bytes(encode_manifest({'schema_version': V2, 'agents': [], 'components': {}}))
            (target / '.gemini').mkdir()
            with mock.patch.dict(os.environ, {'GETZILLA_AGENT': 'codex'}):
                self.assertEqual(INSTALL.detect_agents(target), ())


class FootprintTests(unittest.TestCase):
    def test_plan_reports_every_component_and_adds_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = plan(Path(tmp) / 'absent')
        full = INSTALL.build_payload(ROOT)
        self.assertEqual(sum(item['files'] for item in report['components'].values()), len(full))
        self.assertTrue({'core', 'factory', 'agent:qwen', 'agent:claude'} <= set(report['components']))
        self.assertEqual([item['component'] for item in report['post_install']], ['baseline:security', 'baseline:workflow'])

    def test_default_is_core_plus_one_agent_without_factory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = plan(Path(tmp) / 'absent')
        paths = {entry['path'] for entry in report['entries']}
        self.assertEqual(report['selection'], {'agents': ['qwen'], 'factory': False, 'full': False})
        self.assertFalse(any(path.startswith('factory/') for path in paths))
        self.assertFalse(any(path.startswith(('.claude/', '.codex/', '.gemini/', '.github/agents/')) for path in paths))
        self.assertTrue(any(path.startswith('.qwen/') for path in paths))
        self.assertTrue(any(path.startswith('.agents/skills/') for path in paths))  # one canonical skill source
        self.assertTrue({'AGENTS.md', '.grok/hooks/pre_tool_use.py'} <= paths)
        self.assertLess(len(paths), 400)  # was 672 for every agent plus factory

    def test_agents_flag_and_full_layout_do_not_infer_membership_from_folders(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            chosen = plan(target, '--agents', 'claude,codex')
            self.assertEqual(chosen['selection']['agents'], ['claude', 'codex'])
            (target / '.gemini').mkdir()
            self.assertEqual(plan(target)['selection']['agents'], ['qwen'])
            full = plan(target, '--full-layout')
        self.assertEqual(len(full['entries']), len(INSTALL.build_payload(ROOT)))
        bad = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'install_into.py'), '--plan', '/tmp/x', '--agents', 'notepad'],
                             capture_output=True, text=True, check=False)
        self.assertEqual(bad.returncode, 2)


class OnDemandTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.target = Path(tmp.name) / 'project'
        INSTALL._materialize_new(ROOT, self.target, include_dependencies=False, include_optional=False,
                                 selection=INSTALL.PayloadSelection(('qwen',)))

    def test_lean_project_is_usable(self) -> None:
        self.assertFalse((self.target / 'factory').exists())
        self.assertFalse((self.target / '.claude').exists())
        self.assertTrue((self.target / '.qwen' / 'settings.json').is_file())
        self.assertTrue(is_installed_project(self.target))
        doctor = subprocess.run([sys.executable, str(self.target / 'scripts' / 'getzilla_doctor.py')], cwd=self.target,
                                capture_output=True, text=True, timeout=300, check=False)
        failing = [line for line in doctor.stdout.splitlines() if line.startswith('FAIL') and
                   ('.claude' in line or '.codex' in line or 'factory' in line)]
        self.assertEqual(failing, [], doctor.stdout[-2000:])

    def test_second_agent_is_added_on_demand_and_recorded(self) -> None:
        added = ensure_components(self.target, ['agent:codex'], source=ROOT)
        self.assertTrue(added[0].files)
        self.assertTrue((self.target / '.codex' / 'hooks.json').is_file())
        manifest = load_manifest(self.target)
        self.assertIn('agent:codex', manifest['components'])
        self.assertTrue((self.target / MANIFEST).is_file())
        again = ensure_components(self.target, ['agent:codex'], source=ROOT)
        self.assertEqual(again[0].files, [])

    def test_zero_copy_add_records_intent_and_does_not_rewrite_on_retry(self) -> None:
        from getzilla.component_state import read_state
        for entry in INSTALL.build_payload(ROOT):
            if INSTALL.component_of(entry.path) == 'agent:codex':
                path = self.target / entry.path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(entry.content)
                os.chmod(path, entry.mode)
        added = ensure_components(self.target, ['agent:codex'], source=ROOT)
        self.assertEqual(added[0].files, [])
        self.assertEqual(read_state(self.target).require_selection(), ('qwen', 'codex'))
        before = (self.target / MANIFEST).read_bytes()
        ensure_components(self.target, ['agent:codex'], source=ROOT)
        self.assertEqual((self.target / MANIFEST).read_bytes(), before)

    def test_extra_before_new_agent_uses_the_final_selection(self) -> None:
        ensure_components(self.target, ['extra:bitrix', 'agent:claude'], source=ROOT)
        self.assertTrue((self.target / '.claude/skills/bitrix-development/SKILL.md').is_file())

    def test_legacy_selection_requires_explicit_non_destructive_adoption(self) -> None:
        from getzilla.component_state import V1, read_state
        legacy = {'schema_version': V1, 'components': {'factory': {'files': ['factory/notes.md']}}}
        (self.target / MANIFEST).write_text(json.dumps(legacy))
        before = (self.target / MANIFEST).read_bytes()
        with self.assertRaisesRegex(ValueError, 'adopt'):
            ensure_components(self.target, ['agent:codex'], source=ROOT)
        self.assertEqual((self.target / MANIFEST).read_bytes(), before)
        self.assertFalse((self.target / '.codex').exists())
        from getzilla.on_demand import adopt_selection
        adopt_selection(self.target, ())
        self.assertEqual(read_state(self.target).require_selection(), ())
        self.assertEqual(load_manifest(self.target)['components'], legacy['components'])
        self.assertTrue((self.target / '.qwen/settings.json').exists())
        adopted = (self.target / MANIFEST).read_bytes()
        adopt_selection(self.target, ())
        self.assertEqual((self.target / MANIFEST).read_bytes(), adopted)
        with self.assertRaises(ValueError):
            adopt_selection(self.target, ('qwen',))

    def test_codex_custom_activation_refuses_before_copying_hooks(self) -> None:
        config = self.target / '.codex/config.toml'
        config.parent.mkdir()
        config.write_text('[features]\ncodex_hooks = true\n[my_settings]\nkeep = true\n')
        before = (self.target / MANIFEST).read_bytes()
        with self.assertRaisesRegex(ValueError, 'Codex'):
            ensure_components(self.target, ['agent:codex'], source=ROOT)
        self.assertFalse((self.target / '.codex/hooks.json').exists())
        self.assertEqual((self.target / MANIFEST).read_bytes(), before)
        self.assertIn('[my_settings]', config.read_text())

    def test_interrupted_addition_keeps_old_selection_and_reports_partial_files(self) -> None:
        from getzilla.component_state import ComponentTransaction, read_state
        original = ComponentTransaction.write
        count = 0
        def fail_second(transaction, path, *args, **kwargs):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError('injected publication failure')
            return original(transaction, path, *args, **kwargs)
        before = (self.target / MANIFEST).read_bytes()
        with mock.patch.object(ComponentTransaction, 'write', new=fail_second):
            with self.assertRaisesRegex(ValueError, 'partial files'):
                ensure_components(self.target, ['agent:codex'], source=ROOT)
        self.assertEqual((self.target / MANIFEST).read_bytes(), before)
        self.assertEqual(read_state(self.target).require_selection(), ('qwen',))
        self.assertTrue(any(path.is_file() for path in (self.target / '.codex').rglob('*')))
        ensure_components(self.target, ['agent:codex'], source=ROOT)
        self.assertEqual(read_state(self.target).require_selection(), ('qwen', 'codex'))

    def test_factory_on_demand_never_overwrites(self) -> None:
        own = self.target / 'factory' / 'README.md'
        own.parent.mkdir(parents=True)
        own.write_text('my own factory notes\n', encoding='utf-8')
        added = ensure_components(self.target, ['factory'], source=ROOT)
        self.assertTrue((self.target / 'factory' / 'pyproject.toml').is_file())
        self.assertEqual(own.read_text(encoding='utf-8'), 'my own factory notes\n')
        self.assertIn('factory/README.md', added[0].kept)
        with self.assertRaises(ValueError):
            ensure_components(self.target, ['agent:notepad'], source=ROOT)

    def test_components_cli_requires_an_installed_project(self) -> None:
        cli = [sys.executable, str(ROOT / 'scripts' / 'getzilla_components.py')]
        with tempfile.TemporaryDirectory() as tmp:
            refused = subprocess.run([*cli, 'add', 'factory', '--project', tmp], capture_output=True, text=True)
        self.assertEqual(refused.returncode, 2)
        result = subprocess.run([*cli, 'add', 'agent:claude', '--project', str(self.target)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.target / '.claude' / 'settings.json').is_file())
        with mock.patch.dict(os.environ, {'GETZILLA_AGENT': 'grok'}):
            self.assertEqual(INSTALL.detect_agents(self.target), ('qwen', 'claude'))

    def test_adopt_cli_requires_a_complete_choice_and_resolves_subdirectories(self) -> None:
        (self.target / MANIFEST).unlink()
        subdir = self.target / 'src'
        subdir.mkdir()
        cli = [sys.executable, str(ROOT / 'scripts/getzilla_components.py'), 'adopt']
        absent_choice = subprocess.run(cli, cwd=subdir, capture_output=True, text=True)
        self.assertEqual(absent_choice.returncode, 2)
        self.assertFalse((self.target / MANIFEST).exists())
        explicit_empty = subprocess.run([*cli, '--agents', ''], cwd=subdir, capture_output=True, text=True)
        self.assertEqual(explicit_empty.returncode, 0, explicit_empty.stderr + explicit_empty.stdout)
        self.assertEqual(load_manifest(self.target)['agents'], [])
        self.assertTrue((self.target / '.qwen/settings.json').is_file())


class ComponentPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.source = Path(tmp.name) / 'source'
        self.target = Path(tmp.name) / 'project'
        source_files = {
            'scripts/install_into.py': (ROOT / 'scripts/install_into.py').read_bytes(),
            '.getzilla/templates/consumer-AGENTS.md.tmpl': b'Fixture project instructions\n',
            '.getzilla/templates/consumer-factory-README.md.tmpl': b'Factory notes\n',
            '.getzilla/templates/hook_root_shim.py': b'# Fixture hook shim\n',
            'factory/README.md': b'Factory source notes\n',
            'factory/pyproject.toml': b'[project]\nname = "fixture-factory"\n',
            '.codex/hooks.json': b'{"hooks": []}\n',
            '.codex/config.toml': b'[features]\ncodex_hooks = true\n',
            '.getzilla/compliance/eu-ai-act/rules.json': b'{"rules": []}\n',
            'VERSION': b'fixture-v1\n',
        }
        for relative in INSTALL.MANAGED_FILES:
            source_files.setdefault(relative, b'')
        target_files = {
            '.getzilla/AGBP_SYNC.json': b'{"schema_version": 1}\n',
            '.getzilla/config/compliance.json': b'{"schema_version":"getzilla-compliance-v1","enabled":[]}\n',
            MANIFEST: b'{"schema_version":"getzilla-managed-components-v2","agents":[],"components":{}}\n',
            'factory/README.md': b'My own factory notes\n',
            'local.txt': b'Unrelated user work\n',
        }
        for base, files in ((self.source, source_files), (self.target, target_files)):
            for relative, content in files.items():
                path = base / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        (self.target / 'empty-user-directory').mkdir()

    def snapshot(self) -> dict:
        return {
            path.relative_to(self.target).as_posix(): (
                stat.S_IMODE(path.stat().st_mode), None if path.is_dir() else path.read_bytes()
            )
            for path in self.target.rglob('*')
        }

    def assert_rejected_without_mutation(self, needs: list[str]) -> None:
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, "^unknown component 'agent:notepad'; expected one of "):
            ensure_components(self.target, needs, source=self.source)
        self.assertEqual(self.snapshot(), before)

    def test_unknown_component_after_valid_names_does_not_change_target(self) -> None:
        self.assert_rejected_without_mutation(['factory', 'agent:codex', 'compliance:eu-ai-act', 'agent:notepad'])

    def test_unknown_component_before_valid_names_does_not_change_target(self) -> None:
        self.assert_rejected_without_mutation(['agent:notepad', 'factory', 'agent:codex', 'compliance:eu-ai-act'])

    def test_valid_batch_preserves_order_ownership_and_user_edits(self) -> None:
        needs = ['compliance:eu-ai-act', 'agent:codex', 'factory', 'factory']
        added = ensure_components(self.target, needs, source=self.source)
        self.assertEqual([item.component for item in added], needs)
        self.assertEqual(added[0].files, [
            '.getzilla/compliance/eu-ai-act/rules.json', 'scripts/getzilla_audit_bundle.py',
            'scripts/getzilla_compliance.py',
        ])
        self.assertEqual(added[1].files, ['.codex/config.toml', '.codex/hooks.json'])
        self.assertIn('factory/pyproject.toml', added[2].files)
        self.assertNotIn('factory/README.md', added[2].files)
        self.assertEqual(added[3].files, [])
        self.assertEqual(added[2].kept, ['factory/README.md'])
        self.assertEqual((self.target / 'factory/README.md').read_bytes(), b'My own factory notes\n')
        manifest = load_manifest(self.target)
        self.assertEqual(set(manifest['components']), set(needs) | {'core'})
        for item in added[:3]:
            record = manifest['components'][item.component]
            self.assertEqual(record['files'], item.files)
            self.assertEqual(record['source_version'], 'fixture-v1')
            self.assertTrue(record['added_at'])
        config = json.loads((self.target / '.getzilla/config/compliance.json').read_text(encoding='utf-8'))
        self.assertEqual(config, {'schema_version': 'getzilla-compliance-v1', 'enabled': ['eu-ai-act']})

        custom = self.target / '.codex/hooks.json'
        custom.write_bytes(b'{"user": "custom hooks"}\n')
        before_repeat = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'custom Codex'):
            ensure_components(self.target, needs, source=self.source)
        self.assertEqual(self.snapshot(), before_repeat)


if __name__ == '__main__':
    unittest.main()
