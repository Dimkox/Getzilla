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

    def test_cooperating_publication_between_manifest_stat_and_open_preserves_both_additions(self) -> None:
        from getzilla import fsx
        from getzilla.component_state import component_transaction, encode_manifest, read_state, V2
        (self.root / MANIFEST).write_bytes(encode_manifest({'schema_version': V2, 'agents': [], 'components': {}}))
        def add(name: str) -> None:
            with component_transaction(self.root) as transaction:
                state = read_state(self.root, binding=transaction)
                state.manifest['agents'] = [*state.require_selection(), name]
                transaction.write(MANIFEST, encode_manifest(state.manifest), 0o644,
                                  expected=transaction.read(MANIFEST))
        original = fsx.lstat_at
        published = False
        def publish_after_stat(parent, name):
            nonlocal published
            before = original(parent, name)
            if name == Path(MANIFEST).name and not published:
                published = True
                add('qwen')
            return before
        with mock.patch.object(fsx, 'lstat_at', side_effect=publish_after_stat):
            add('codex')
        self.assertEqual(set(read_state(self.root).require_selection()), {'qwen', 'codex'})

    def test_repeated_prelock_manifest_replacement_refuses_before_creating_the_guard(self) -> None:
        from getzilla import fsx
        from getzilla.component_state import component_transaction, encode_manifest, V2
        manifest = self.root / MANIFEST
        content = encode_manifest({'schema_version': V2, 'agents': [], 'components': {}})
        manifest.write_bytes(content)
        original = fsx.lstat_at
        replacements = 0
        def replace_after_stat(parent, name):
            nonlocal replacements
            before = original(parent, name)
            if name == manifest.name:
                replacements += 1
                replacement = manifest.with_name('next-manifest.json')
                replacement.write_bytes(content)
                replacement.replace(manifest)
            return before
        with mock.patch.object(fsx, 'lstat_at', side_effect=replace_after_stat):
            with self.assertRaisesRegex(ValueError, 'changed'):
                with component_transaction(self.root):
                    self.fail('an unstable pre-lock manifest was admitted')
        self.assertLessEqual(replacements, 6, 'pre-lock retries must remain bounded')
        self.assertFalse((self.root / '.getzilla/runtime').exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX detached read descriptor semantics')
    def test_cooperating_publication_during_manifest_read_preserves_both_additions(self) -> None:
        from getzilla import fsx
        from getzilla.component_state import component_transaction, encode_manifest, read_state, V2
        (self.root / MANIFEST).write_bytes(encode_manifest({'schema_version': V2, 'agents': [], 'components': {}}))
        def add(name: str) -> None:
            with component_transaction(self.root) as transaction:
                state = read_state(self.root, binding=transaction)
                state.manifest['agents'] = [*state.require_selection(), name]
                transaction.write(MANIFEST, encode_manifest(state.manifest), 0o644,
                                  expected=transaction.read(MANIFEST))
        real_open, real_read = fsx.open_at, os.read
        reader = None
        published = False
        def remember_reader(parent, name, flags, *args):
            nonlocal reader
            descriptor = real_open(parent, name, flags, *args)
            if name == Path(MANIFEST).name and reader is None:
                reader = descriptor
            return descriptor
        def publish_after_read(descriptor, size):
            nonlocal published
            content = real_read(descriptor, size)
            if descriptor == reader and not published:
                published = True
                add('qwen')
            return content
        with mock.patch.object(fsx, 'open_at', side_effect=remember_reader), \
                mock.patch.object(os, 'read', side_effect=publish_after_read):
            add('codex')
        self.assertEqual(set(read_state(self.root).require_selection()), {'qwen', 'codex'})

    def test_invalid_prelock_manifest_is_not_retried_or_used_to_create_the_guard(self) -> None:
        from getzilla import fsx
        from getzilla.component_state import component_transaction, encode_manifest, V2
        manifest = self.root / MANIFEST
        manifest.write_bytes(b'{')
        original = fsx.lstat_at
        reads = 0
        def valid_on_retry(parent, name):
            nonlocal reads
            if name == manifest.name:
                reads += 1
                if reads > 2:
                    manifest.write_bytes(encode_manifest({'schema_version': V2, 'agents': [], 'components': {}}))
            return original(parent, name)
        with mock.patch.object(fsx, 'lstat_at', side_effect=valid_on_retry):
            with self.assertRaises(ValueError):
                with component_transaction(self.root):
                    self.fail('invalid state was retried into acceptance')
        self.assertEqual(manifest.read_bytes(), b'{')
        self.assertFalse((self.root / '.getzilla/runtime').exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX hardlink semantics')
    def test_prelock_hardlink_replacement_is_not_retried(self) -> None:
        from getzilla import fsx
        from getzilla.component_state import component_transaction, encode_manifest, V2
        content = encode_manifest({'schema_version': V2, 'agents': [], 'components': {}})
        manifest = self.root / MANIFEST
        manifest.write_bytes(content)
        outside = self.root.parent / 'outside.json'
        outside.write_bytes(content)
        original = fsx.lstat_at
        observations = 0
        def replace_after_stat(parent, name):
            nonlocal observations
            before = original(parent, name)
            if name == manifest.name:
                observations += 1
                replacement = manifest.with_name('next-manifest.json')
                if observations == 1:
                    os.link(outside, replacement)
                    replacement.replace(manifest)
                elif observations > 2:
                    replacement.write_bytes(content)
                    replacement.replace(manifest)
            return before
        with mock.patch.object(fsx, 'lstat_at', side_effect=replace_after_stat):
            with self.assertRaises(ValueError):
                with component_transaction(self.root):
                    self.fail('an unsafe replacement was retried into acceptance')
        self.assertEqual(manifest.stat().st_nlink, 2)
        self.assertEqual(outside.read_bytes(), content)
        self.assertFalse((self.root / '.getzilla/runtime').exists())

    def test_manifest_replacement_after_lock_acquisition_is_not_retried(self) -> None:
        from getzilla import fsx
        from getzilla.component_state import component_transaction, encode_manifest, V2
        content = encode_manifest({'schema_version': V2, 'agents': [], 'components': {}})
        manifest = self.root / MANIFEST
        manifest.write_bytes(content)
        real_lock, real_stat = fsx.lock_file, fsx.lstat_at
        locked = False
        replaced = False
        def acquire(descriptor, *, blocking):
            nonlocal locked
            real_lock(descriptor, blocking=blocking)
            locked = True
        def replace_after_stat(parent, name):
            nonlocal replaced
            before = real_stat(parent, name)
            if locked and name == manifest.name and not replaced:
                replaced = True
                replacement = manifest.with_name('next-manifest.json')
                replacement.write_bytes(content)
                replacement.replace(manifest)
            return before
        with mock.patch.object(fsx, 'lock_file', side_effect=acquire), \
                mock.patch.object(fsx, 'lstat_at', side_effect=replace_after_stat):
            with self.assertRaisesRegex(ValueError, 'changed'):
                with component_transaction(self.root):
                    self.fail('a changed under-lock manifest was retried into acceptance')

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
    def test_shipped_components_removal_uses_full_source_once_in_both_layouts(self) -> None:
        from getzilla.component_state import read_state
        environment = {**os.environ, 'GETZILLA_HOME': str(ROOT), 'PYTHONDONTWRITEBYTECODE': '1',
                       'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1',
                       'GIT_AUTHOR_NAME': 'public fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                       'GIT_COMMITTER_NAME': 'public fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
        with tempfile.TemporaryDirectory() as tmp:
            for archive in (False, True):
                with self.subTest(archive=archive):
                    target = Path(tmp) / str(archive)
                    INSTALL._materialize_new(ROOT, target, include_dependencies=False, include_optional=False,
                                             selection=INSTALL.PayloadSelection(('codex',), engine_archive=archive))
                    script = target / 'scripts/getzilla_components.py'
                    self.assertTrue(script.is_file())
                    self.assertFalse((target / 'scripts/getzilla_upgrade.py').exists())
                    unknown = target / '.codex/user.txt'
                    unknown.write_bytes(b'public foreign bytes\n')
                    engine = target / INSTALL.ENGINE_ARCHIVE if archive else target / '.getzilla/getzilla/harnesses.py'
                    engine_before = engine.read_bytes()

                    def git(*args):
                        return subprocess.run(['git', '-C', str(target), *args], env=environment,
                                              capture_output=True, text=True, check=True).stdout.strip()

                    git('init', '--quiet', '--initial-branch=main')
                    git('add', '-A')
                    git('commit', '--quiet', '-m', 'shipped consumer public fixture')
                    original = git('rev-parse', 'HEAD')
                    result = subprocess.run([sys.executable, '-B', str(script), 'remove', 'agent:codex'],
                                            cwd=target, env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(json.loads(result.stdout)['live_client_state'], 'unverified')
                    removed = git('rev-parse', 'HEAD')
                    self.assertEqual(git('rev-parse', 'HEAD^'), original)
                    self.assertEqual(read_state(target).require_selection(), ())
                    again = subprocess.run([sys.executable, '-B', str(script), 'uninstall'], cwd=target,
                                           env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
                    self.assertEqual(json.loads(again.stdout)['configuration'], 'unchanged')
                    self.assertEqual(git('rev-parse', 'HEAD'), removed)
                    self.assertEqual(len(git('for-each-ref', '--format=%(refname)', 'refs/heads').splitlines()), 2)
                    self.assertEqual(unknown.read_bytes(), b'public foreign bytes\n')
                    self.assertEqual(engine.read_bytes(), engine_before)
                    module_status = subprocess.run([sys.executable, '-B', str(script), 'module', 'status'], cwd=target,
                                                   env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual(module_status.returncode, 0, module_status.stdout + module_status.stderr)

    def test_shipped_removal_refuses_unavailable_or_incomplete_source_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / 'project'
            INSTALL._materialize_new(ROOT, target, include_dependencies=False, include_optional=False,
                                     selection=INSTALL.PayloadSelection(('codex',), engine_archive=True))
            home = base / 'empty-home'
            home.mkdir()
            source = base / 'source'
            source.mkdir()
            marker = base / 'unexpected-launch'
            environment = {**os.environ, 'GETZILLA_HOME': str(source), 'HOME': str(home), 'USERPROFILE': str(home),
                           'PYTHONDONTWRITEBYTECODE': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
            manifest = (target / MANIFEST).read_bytes()
            role = (target / '.codex/agents/general_implementer.toml').read_bytes()
            for scenario in ('unavailable', 'incomplete'):
                with self.subTest(scenario=scenario):
                    if scenario == 'incomplete':
                        (source / 'scripts').mkdir()
                        (source / 'factory').mkdir()
                        (source / 'scripts/install_into.py').write_bytes(b'# inert fixture marker\n')
                        (source / 'factory/pyproject.toml').write_bytes(b'# inert fixture marker\n')
                        (source / 'scripts/getzilla_components.py').write_text(
                            'from pathlib import Path\nPath(' + repr(str(marker)) + ').write_text("launched")\n')
                    result = subprocess.run([sys.executable, '-B', str(target / 'scripts/getzilla_components.py'), 'uninstall'],
                                            cwd=target, env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertFalse(json.loads(result.stdout)['ok'])
                    self.assertIn('source', json.loads(result.stdout)['error'])
                    self.assertFalse(marker.exists())
                    self.assertEqual((target / MANIFEST).read_bytes(), manifest)
                    self.assertEqual((target / '.codex/agents/general_implementer.toml').read_bytes(), role)

    def test_installed_removal_forwards_nonzero_result_once_without_overriding_context(self) -> None:
        spec = importlib.util.spec_from_file_location('installed_forwarding_control', ROOT / 'scripts/getzilla_components.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'project'
            INSTALL._materialize_new(ROOT, target, include_dependencies=False, include_optional=False,
                                     selection=INSTALL.PayloadSelection(('codex',)))
            manifest = (target / MANIFEST).read_bytes()
            arguments = ['remove', 'agent:codex']
            for outcome in ('nonzero', 'uncertain'):
                with self.subTest(outcome=outcome), mock.patch.object(module, 'ROOT', target), \
                        mock.patch.object(module, 'getzilla_home', return_value=ROOT), \
                        mock.patch.object(module, 'find_installed_project', return_value=target), \
                        mock.patch.object(subprocess, 'run') as forward:
                    if outcome == 'nonzero':
                        forward.return_value = subprocess.CompletedProcess([], 37)
                    else:
                        forward.side_effect = OSError('public fixture launch uncertainty')
                    self.assertEqual(module.main(arguments), 37 if outcome == 'nonzero' else 2)
                    forward.assert_called_once_with([sys.executable, str(ROOT / 'scripts/getzilla_components.py'), *arguments], check=False)
                    self.assertEqual((target / MANIFEST).read_bytes(), manifest)

    def test_grok_removal_includes_stock_native_briefs_and_config_only(self) -> None:
        sys.path.insert(0, str(ROOT / 'scripts'))
        import getzilla_upgrade
        environment = {'GIT_AUTHOR_NAME': 'public fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                       'GIT_COMMITTER_NAME': 'public fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, environment):
            target = Path(tmp) / 'project'
            INSTALL._materialize_new(ROOT, target, include_dependencies=False, include_optional=False,
                                     selection=INSTALL.PayloadSelection(('grok',)))
            custom = target / '.grok/agents/consumer_custom.md'
            custom.write_bytes(b'# public user agent\n')
            for args in (('init', '--quiet', '--initial-branch=main'), ('add', '-A'),
                         ('commit', '--quiet', '-m', 'Grok installed public fixture')):
                subprocess.run(['git', '-C', str(target), *args], check=True, capture_output=True)
            self.assertTrue((target / '.grok/agents/general_implementer.md').is_file())
            getzilla_upgrade.remove_adapters(ROOT, target)
            self.assertFalse((target / '.grok/agents/general_implementer.md').exists())
            self.assertFalse((target / '.grok/config.toml').exists())
            self.assertEqual(custom.read_bytes(), b'# public user agent\n')

    def test_git_backed_adapter_removal_readd_and_empty_selection_in_both_layouts(self) -> None:
        from getzilla.component_state import agent_of, read_state
        sys.path.insert(0, str(ROOT / 'scripts'))
        import getzilla_upgrade
        environment = {**os.environ, 'GIT_AUTHOR_NAME': 'public fixture',
                       'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                       'GIT_COMMITTER_NAME': 'public fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid',
                       'PYTHONDONTWRITEBYTECODE': '1'}
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, environment):
            for archive in (False, True):
                with self.subTest(archive=archive):
                    target = Path(tmp) / str(archive)
                    INSTALL._materialize_new(ROOT, target, include_dependencies=False, include_optional=False,
                                             selection=INSTALL.PayloadSelection(('codex', 'qwen'), engine_archive=archive))
                    foreign = target / '.codex/foreign.txt'
                    foreign.write_bytes(b'public unknown file\n')
                    old_helper = target / '.grok/hooks/custom.py'
                    old_helper.parent.mkdir(parents=True, exist_ok=True)
                    old_helper.write_bytes(b'# retained custom helper\n')
                    deep = target / 'src/deep'
                    deep.mkdir(parents=True)

                    def git(*args):
                        return subprocess.run(['git', '-C', str(target), *args], env=environment,
                                              check=True, capture_output=True, text=True).stdout.strip()

                    git('init', '--quiet', '--initial-branch=main')
                    git('add', '-A')
                    git('commit', '--quiet', '-m', 'installed public fixture')
                    original = git('rev-parse', 'HEAD')
                    engine = target / INSTALL.ENGINE_ARCHIVE if archive else target / '.getzilla/getzilla/harnesses.py'
                    engine_before = engine.read_bytes()
                    for arguments in (('remove', 'agent:qwen'), ('uninstall',)):
                        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/getzilla_components.py'), *arguments],
                                                cwd=deep, env=environment, capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertEqual(json.loads(result.stdout)['live_client_state'], 'unverified')
                    self.assertEqual(read_state(target).require_selection(), ())
                    self.assertEqual(foreign.read_bytes(), b'public unknown file\n')
                    self.assertEqual(old_helper.read_bytes(), b'# retained custom helper\n')
                    self.assertIn('entire hooks codex', (target / '.codex/hooks.json').read_text())
                    self.assertEqual(engine.read_bytes(), engine_before)
                    head = git('rev-parse', 'HEAD')
                    again = getzilla_upgrade.remove_adapters(ROOT, target)
                    self.assertEqual(again['configuration'], 'unchanged')
                    self.assertEqual(git('rev-parse', 'HEAD'), head)
                    generated = subprocess.run([sys.executable, '-B', str(target / 'scripts/getzilla_harness.py'), '--write'],
                                               cwd=deep, env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)
                    self.assertFalse((target / '.qwen/settings.json').exists())
                    updates = getzilla_upgrade.planned_changes(getzilla_upgrade.load_installer(ROOT), ROOT, target)
                    self.assertFalse(any(agent_of(path) for path, _, _ in updates))
                    ensure_components(target, ['agent:codex', 'agent:qwen'], source=ROOT)
                    self.assertEqual(read_state(target).require_selection(), ('codex', 'qwen'))
                    commands = (target / '.codex/hooks.json').read_text()
                    self.assertIn('.getzilla/hooks/', commands)
                    self.assertEqual(commands.count('entire hooks codex stop'), 1)
                    self.assertTrue((target / '.qwen/settings.json').exists())
                    git('add', '-A')
                    git('commit', '--quiet', '-m', 're-add adapters')
                    git('switch', '--quiet', 'main')
                    self.assertEqual(git('rev-parse', 'HEAD'), original)
                    self.assertEqual(read_state(target).require_selection(), ('codex', 'qwen'))

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
                    (target / '.getzilla/agents/consumer_only.toml').write_bytes(custom_source)
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
        self.assertTrue({'AGENTS.md', '.getzilla/hooks/pre_tool_use.py'} <= paths)
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

    def test_stock_codex_reactivation_refuses_custom_or_kept_remainders(self) -> None:
        from getzilla.adapter_removal import codex_retained_configuration
        from getzilla.component_state import read_state
        hooks = self.target / '.codex/hooks.json'
        hooks.parent.mkdir()
        overlay = (ROOT / '.getzilla/config/codex-hooks.json').read_bytes()
        stock = codex_retained_configuration((ROOT / '.getzilla/config/hooks.json').read_bytes(), overlay)
        config = self.target / '.codex/config.toml'
        config.write_bytes(b'[features]\ncodex_hooks = true\n')
        config.chmod(0o644)
        for scenario in ('foreign-group', 'mode', 'kept', 'custom-overlay'):
            with self.subTest(scenario=scenario):
                hooks.write_bytes(stock)
                hooks.chmod(0o644)
                if scenario == 'foreign-group':
                    data = json.loads(stock)
                    data['hooks']['Stop'].append({'hooks': [{'command': 'echo public foreign'}]})
                    hooks.write_text(json.dumps(data))
                elif scenario == 'mode':
                    hooks.chmod(0o755)
                elif scenario == 'kept':
                    (self.target / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
                        'schema_version': 1, 'kept_local': ['.codex/hooks.json']}))
                else:
                    (self.target / '.getzilla/AGBP_SYNC.json').unlink()
                    (self.target / '.getzilla/config/codex-hooks.json').write_bytes(overlay + b'\n')
                before = (self.target / MANIFEST).read_bytes()
                saved = hooks.read_bytes()
                with self.assertRaisesRegex(ValueError, 'Codex'):
                    ensure_components(self.target, ['agent:codex'], source=ROOT)
                self.assertEqual(hooks.read_bytes(), saved)
                self.assertEqual((self.target / MANIFEST).read_bytes(), before)
                self.assertEqual(read_state(self.target).require_selection(), ('qwen',))

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

    def keep(self, path: str, content: bytes | None) -> None:
        record = {'schema_version': 1, 'kept_local': [path], 'kept_local_sha256': {}}
        if content is not None:
            record['kept_local_sha256'][path] = hashlib.sha256(content).hexdigest()
        (self.target / '.getzilla/AGBP_SYNC.json').write_text(json.dumps(record))

    def test_declared_keep_loses_owned_proof_and_cannot_reclaim_it(self) -> None:
        ensure_components(self.target, ['factory'], source=self.source)
        path = 'factory/pyproject.toml'
        for content in ((self.target / path).read_bytes(), b'My custom project metadata\n'):
            with self.subTest(content=content):
                (self.target / path).write_bytes(content)
                self.keep(path, content)
                for _ in range(2):
                    added = ensure_components(self.target, ['factory'], source=self.source)
                    self.assertIn(path, added[0].kept)
                    self.assertEqual((self.target / path).read_bytes(), content)
                    record = load_manifest(self.target)['components']['factory']
                    self.assertIn(path, record['files'])
                    self.assertNotIn(path, record.get('owned', {}))

    def test_absent_declared_keep_refuses_entire_addition_before_writes(self) -> None:
        self.keep('factory/pyproject.toml', None)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'kept'):
            ensure_components(self.target, ['compliance:eu-ai-act', 'factory'], source=self.source)
        self.assertEqual(self.snapshot(), before)

    def test_kept_manifest_refuses_add_before_files_or_selection_change(self) -> None:
        self.keep(MANIFEST, (self.target / MANIFEST).read_bytes())
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'kept.*manifest'):
            ensure_components(self.target, ['factory', 'agent:codex'], source=self.source)
        self.assertEqual(self.snapshot(), before)

    def test_kept_manifest_allows_same_component_noop(self) -> None:
        ensure_components(self.target, ['factory'], source=self.source)
        self.keep(MANIFEST, (self.target / MANIFEST).read_bytes())
        before = self.snapshot()
        added = ensure_components(self.target, ['factory'], source=self.source)
        self.assertEqual(added[0].files, [])
        self.assertEqual(self.snapshot(), before)

    def test_kept_manifest_refuses_adoption_but_allows_same_selection(self) -> None:
        from getzilla.component_state import V1, V2
        from getzilla.on_demand import adopt_selection
        legacy = json.dumps({'schema_version': V1, 'components': {}}).encode()
        (self.target / MANIFEST).write_bytes(legacy)
        self.keep(MANIFEST, legacy)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'kept.*manifest'):
            adopt_selection(self.target, ())
        self.assertEqual(self.snapshot(), before)
        selected = json.dumps({'schema_version': V2, 'agents': [], 'components': {}}).encode()
        (self.target / MANIFEST).write_bytes(selected)
        self.keep(MANIFEST, selected)
        before = self.snapshot()
        adopt_selection(self.target, ())
        self.assertEqual(self.snapshot(), before)

    def test_stale_keep_digest_refuses_even_identical_addition_before_writes(self) -> None:
        path = 'factory/pyproject.toml'
        (self.target / path).write_bytes((self.source / path).read_bytes())
        self.keep(path, b'Previously accepted different bytes\n')
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'digest'):
            ensure_components(self.target, ['compliance:eu-ai-act', 'factory'], source=self.source)
        self.assertEqual(self.snapshot(), before)

    def test_keep_without_digest_refuses_divergent_addition(self) -> None:
        self.keep('factory/README.md', None)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'kept'):
            ensure_components(self.target, ['factory'], source=self.source)
        self.assertEqual(self.snapshot(), before)

    def test_kept_compliance_config_cannot_be_silently_enabled(self) -> None:
        path = '.getzilla/config/compliance.json'
        self.keep(path, (self.target / path).read_bytes())
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'kept'):
            ensure_components(self.target, ['factory', 'compliance:eu-ai-act'], source=self.source)
        self.assertEqual(self.snapshot(), before)

    def test_enabled_kept_compliance_config_retains_bytes_without_ownership(self) -> None:
        ensure_components(self.target, ['compliance:eu-ai-act'], source=self.source)
        path = '.getzilla/config/compliance.json'
        content = b'{"enabled":["eu-ai-act"],"schema_version":"getzilla-compliance-v1"}\n'
        (self.target / path).write_bytes(content)
        self.keep(path, content)
        added = ensure_components(self.target, ['compliance:eu-ai-act'], source=self.source)
        self.assertEqual((self.target / path).read_bytes(), content)
        self.assertIn(path, added[0].kept)
        record = load_manifest(self.target)['components']['core']
        self.assertIn(path, record['files'])
        self.assertNotIn(path, record.get('owned', {}))

    def test_identical_compliance_config_preserves_custom_mode_without_ownership(self) -> None:
        from getzilla.component_state import encode_manifest, record_owned, V2
        relative = '.getzilla/config/compliance.json'
        config = self.target / relative
        content = (json.dumps({'schema_version': 'getzilla-compliance-v1', 'enabled': ['eu-ai-act']},
                              indent=2, sort_keys=True) + '\n').encode()
        for previously_owned in (False, True):
            with self.subTest(previously_owned=previously_owned):
                config.chmod(0o644)
                config.write_bytes(content)
                config.chmod(0o400 if os.name == 'nt' else 0o600)
                before_mode = stat.S_IMODE(config.stat().st_mode)
                manifest = {'schema_version': V2, 'agents': [], 'components': {}}
                if previously_owned:
                    record_owned(manifest, relative, content, 0o644)
                (self.target / MANIFEST).write_bytes(encode_manifest(manifest))
                added = ensure_components(self.target, ['compliance:eu-ai-act'], source=self.source)
                self.assertEqual(config.read_bytes(), content)
                self.assertEqual(stat.S_IMODE(config.stat().st_mode), before_mode)
                records = load_manifest(self.target)['components'].values()
                self.assertFalse(any(relative in record.get('owned', {}) for record in records))
                self.assertIn(relative, added[0].kept)

    def test_identical_compliance_config_claims_only_matching_byte_and_mode_baseline(self) -> None:
        from getzilla.component_state import BoundRoot, matches_owned, owned_proof
        relative = '.getzilla/config/compliance.json'
        config = self.target / relative
        content = (json.dumps({'schema_version': 'getzilla-compliance-v1', 'enabled': ['eu-ai-act']},
                              indent=2, sort_keys=True) + '\n').encode()
        config.write_bytes(content)
        config.chmod(0o644)
        added = ensure_components(self.target, ['compliance:eu-ai-act'], source=self.source)
        with BoundRoot(self.target) as binding:
            self.assertTrue(matches_owned(binding.read(relative), owned_proof(load_manifest(self.target), relative)))
        self.assertNotIn(relative, added[0].kept)

    def test_kept_codex_pair_refuses_if_either_member_is_missing(self) -> None:
        config, hooks = '.codex/config.toml', '.codex/hooks.json'
        for index, (kept, missing) in enumerate(((config, config), (hooks, hooks),
                                                (config, hooks), (hooks, config))):
            with self.subTest(kept=kept, missing=missing):
                target = self.target / f'pair-{index}'
                (target / '.getzilla').mkdir(parents=True)
                (target / '.codex').mkdir()
                (target / MANIFEST).write_bytes((self.target / MANIFEST).read_bytes())
                (target / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
                    'schema_version': 1, 'kept_local': [kept],
                    'kept_local_sha256': {kept: hashlib.sha256((self.source / kept).read_bytes()).hexdigest()},
                }))
                for path in (config, hooks):
                    if path != missing:
                        (target / path).write_bytes((self.source / path).read_bytes())
                before = self.snapshot()
                with self.assertRaisesRegex(ValueError, 'Codex'):
                    ensure_components(target, ['factory', 'agent:codex'], source=self.source)
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
