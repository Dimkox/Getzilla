"""Explicit migration from the actual pinned historical materializer."""
from __future__ import annotations

import hashlib
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'scripts'), str(ROOT / '.getzilla')]
import getzilla_upgrade as upgrade  # noqa: E402
from getzilla.component_state import MANIFEST, encode_manifest, mode_matches, read_state, record_owned  # noqa: E402

STABLE = '2bb417431f1e4b9494e4af71ebf27adb1d04d898'


class HistoricalUpgradeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temporary.name).resolve()
        cls.base.chmod(0o700)
        cls.environment = {**os.environ, 'GIT_CEILING_DIRECTORIES': str(cls.base),
                           'GIT_AUTHOR_NAME': 'fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                           'GIT_COMMITTER_NAME': 'fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid',
                           'PYTHONDONTWRITEBYTECODE': '1'}
        source = cls.base / 'historical-source'
        cls.source = source
        cls.run_process(['git', 'clone', '--quiet', '--no-hardlinks', str(ROOT), str(source)])
        cls.run_process(['git', '-C', str(source), 'checkout', '--quiet', '--detach', STABLE])
        cls.fixture = cls.base / 'historical-install'
        mask = os.umask(0o022)
        try:
            cls.run_process([sys.executable, str(source / 'scripts/install_into.py'),
                             '--materialize-new', str(cls.fixture), '--agents', 'qwen'])
        finally:
            os.umask(mask)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def run_process(cls, args, cwd=None):
        return subprocess.run(args, cwd=cwd, env=cls.environment, check=True,
                              capture_output=True, text=True, timeout=90).stdout.strip()

    def setUp(self):
        self.project = self.base / self._testMethodName
        shutil.copytree(self.fixture, self.project)
        self.run_process(['git', 'init', '--quiet', '--initial-branch=main'], self.project)
        self.run_process([sys.executable, str(ROOT / 'scripts/getzilla_components.py'),
                          'adopt', '--agents', 'qwen'], self.project)
        (self.project / 'user.txt').write_text('keep my work\n')
        self.commit()
        self.before = self.git('rev-parse', 'HEAD')

    def git(self, *args):
        return self.run_process(['git', *args], self.project)

    def commit(self):
        self.git('add', '-A')
        self.git('commit', '--quiet', '-m', 'historical installation and user files')

    def update(self, **kwargs):
        with mock.patch.dict(os.environ, self.environment):
            return upgrade.sync_project(ROOT, self.project, baseline_release='v2.3.0', **kwargs)

    def stock_ignored_runtime(self):
        # The stock install.sh --create route invokes this exact historical
        # materializer. Native acceptance then adds this project ignore rule.
        anchors = ('.getzilla/runtime/.gitignore', '.getzilla/runtime/.gitkeep')
        self.assertEqual((self.project / anchors[0]).read_bytes(),
            b'# Getzilla runtime state (receipts, metrics, counters, worktrees) is machine-local and never committed.\n'
            b'# This file ships with Getzilla so a project needs no root .gitignore rule for it.\n*\n!.gitignore\n!.gitkeep\n')
        self.assertEqual((self.project / anchors[1]).read_bytes(), b'')
        self.git('rm', '--cached', '--', *anchors)
        (self.project / '.gitignore').write_text('.getzilla/runtime/\n')
        self.commit()
        self.before = self.git('rev-parse', 'HEAD')
        sentinel = self.project / '.getzilla/runtime/user-sentinel.bin'
        sentinel.write_bytes(b'ignored user data\x00\xff')
        return anchors, sentinel

    def test_stock_ignored_runtime_anchors_survive_upgrade_and_rollback_untracked(self):
        anchors, sentinel = self.stock_ignored_runtime()
        def identity(path):
            value = (self.project/path).stat()
            return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns
        before = {path: identity(path) for path in anchors}
        directory = (self.project / '.getzilla/runtime').stat()
        self.update()
        self.assertEqual(self.git('ls-files', '--', *anchors), '')
        for path in anchors:
            self.assertEqual(identity(path), before[path])
        self.assertEqual((self.project/'.getzilla/runtime').stat().st_mode, directory.st_mode)
        self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')
        self.git('switch', '--quiet', 'main')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.before)
        for path in anchors:
            self.assertEqual(identity(path), before[path])
        self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_unproved_ignored_runtime_anchors_remain_a_collision(self):
        anchors, sentinel = self.stock_ignored_runtime()
        self.update()
        manifest = read_state(self.project).manifest
        for component in manifest['components'].values():
            for path in anchors:
                component['owned'].pop(path, None)
        (self.project/MANIFEST).write_bytes(encode_manifest(manifest))
        self.commit()
        self.before = self.git('rev-parse', 'HEAD')
        with self.assertRaisesRegex(upgrade.UpdateError, 'ignored local files'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.before)
        self.assertTrue(all((self.project/path).is_file() for path in anchors))
        self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')

    def test_already_owned_ignored_anchors_are_idempotent_without_baseline(self):
        anchors, sentinel = self.stock_ignored_runtime()
        self.update()
        head = self.git('rev-parse', 'HEAD')
        result = upgrade.sync_project(ROOT, self.project)
        self.assertIn('is up to date', result)
        self.assertEqual(self.git('rev-parse', 'HEAD'), head)
        self.assertEqual(self.git('ls-files', '--', *anchors), '')
        self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')

    def test_changed_ignored_runtime_anchor_refuses_before_publication(self):
        anchors, sentinel = self.stock_ignored_runtime()
        (self.project/anchors[0]).write_bytes(b'# user ignore rules\n*\n')
        with self.assertRaisesRegex(upgrade.UpdateError, 'ownership conflict'):
            self.update()
        self.assertEqual(self.git('branch', '--list'), '* main')
        self.assertEqual((self.project/anchors[0]).read_bytes(), b'# user ignore rules\n*\n')
        self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')

    def test_missing_ignored_anchor_is_created_without_claiming_old_bytes(self):
        anchors, sentinel = self.stock_ignored_runtime()
        (self.project/anchors[1]).unlink()
        self.update()
        self.assertEqual(self.git('ls-files', '--', *anchors), anchors[1])
        self.assertEqual((self.project/anchors[1]).read_bytes(), b'')
        self.git('switch', '--quiet', 'main')
        self.assertFalse((self.project/anchors[1]).exists())
        self.assertTrue((self.project/anchors[0]).is_file())
        self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')

    def test_foreign_ignored_identical_file_is_not_historical_ownership(self):
        _anchors, sentinel = self.stock_ignored_runtime()
        target = self.project/'scripts/getzilla_platform_install.py'
        self.assertFalse(target.exists())
        with (self.project/'.gitignore').open('a') as stream:
            stream.write('scripts/getzilla_platform_install.py\n')
        self.commit()
        target.write_bytes((ROOT/'scripts/getzilla_platform_install.py').read_bytes())
        with self.assertRaisesRegex(upgrade.UpdateError, 'ignored local files'):
            self.update()
        self.assertEqual(target.read_bytes(), (ROOT/'scripts/getzilla_platform_install.py').read_bytes())
        self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')

    def test_proved_ignored_old_file_that_needs_replacement_is_not_overwritten(self):
        _anchors, sentinel = self.stock_ignored_runtime()
        path = 'scripts/getzilla_route.py'
        original = (self.project/path).read_bytes()
        self.assertNotEqual(original, (ROOT/path).read_bytes())
        self.git('rm', '--cached', '--', path)
        with (self.project/'.gitignore').open('a') as stream:
            stream.write(path+'\n')
        self.commit()
        with self.assertRaisesRegex(upgrade.UpdateError, 'ignored local files'):
            self.update()
        self.assertEqual((self.project/path).read_bytes(), original)
        self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')

    def test_ignored_anchor_commit_failure_and_cas_preserve_runtime(self):
        anchors, sentinel = self.stock_ignored_runtime()
        original = (self.project/anchors[0]).read_bytes()
        with mock.patch.object(upgrade, 'commit_changes', side_effect=upgrade.UpdateError('private commit failed')):
            with self.assertRaisesRegex(upgrade.UpdateError, 'private commit failed'):
                self.update()
        self.assertEqual(self.git('branch', '--list'), '* main')
        self.assertEqual((self.project/anchors[0]).read_bytes(), original)
        real_commit = upgrade.commit_changes

        def changed_during_commit(*args, **kwargs):
            result = real_commit(*args, **kwargs)
            (self.project/anchors[0]).write_bytes(b'# concurrent user edit\n')
            return result

        with mock.patch.object(upgrade, 'commit_changes', side_effect=changed_during_commit):
            with self.assertRaisesRegex(upgrade.UpdateError, 'changed during the update'):
                self.update()
        self.assertEqual(self.git('branch', '--list'), '* main')
        self.assertEqual((self.project/anchors[0]).read_bytes(), b'# concurrent user edit\n')
        self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')

    def retained_anchor_replacement(self, phase):
        anchors, sentinel = self.stock_ignored_runtime()
        target = self.project/anchors[0]
        original = target.stat()
        content = target.read_bytes()
        replacements = []

        def replace():
            incoming = target.with_name('foreign-replacement')
            incoming.write_bytes(content)
            incoming.chmod(original.st_mode & 0o777)
            incoming.replace(target)
            replacements.append(target.stat())

        real_plan, real_commit, real_git = upgrade.planned_changes, upgrade.commit_changes, upgrade.git

        def planned(*args, **kwargs):
            result = real_plan(*args, **kwargs)
            if phase == 'planning':
                replace()
            return result

        def committed(*args, **kwargs):
            result = real_commit(*args, **kwargs)
            if phase == 'commit':
                replace()
            return result

        def switched(project, *args, **kwargs):
            result = real_git(project, *args, **kwargs)
            if phase == 'checkout' and args[0] == 'switch' and result.returncode == 0:
                replace()
            return result

        message = 'retained.*update incomplete after checkout' if phase == 'checkout' else 'changed during the update'
        with mock.patch.object(upgrade, 'planned_changes', side_effect=planned), \
                mock.patch.object(upgrade, 'commit_changes', side_effect=committed), \
                mock.patch.object(upgrade, 'git', side_effect=switched):
            with self.assertRaisesRegex(upgrade.UpdateError, message):
                self.update()
        self.assertEqual(len(replacements), 1)
        replacement = replacements[0]
        self.assertNotEqual((original.st_dev, original.st_ino), (replacement.st_dev, replacement.st_ino))
        self.assertEqual((target.stat().st_dev, target.stat().st_ino), (replacement.st_dev, replacement.st_ino))
        self.assertEqual(target.read_bytes(), content)
        self.assertEqual(target.stat().st_mode, original.st_mode)
        self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')
        self.assertEqual(self.git('rev-parse', 'main'), self.before)
        if phase == 'checkout':
            branch = upgrade.BRANCH_PREFIX + upgrade.version_of(ROOT)
            recovery = self.git('rev-parse', branch)
            self.assertEqual(self.git('branch', '--show-current'), branch)
            self.assertEqual(self.git('rev-parse', 'HEAD'), recovery)
            self.assertNotEqual(recovery, self.before)
            self.assertEqual(self.git('status', '--porcelain'), '')
            self.git('switch', '--quiet', 'main')
            self.assertEqual(self.git('rev-parse', branch), recovery)
            self.assertEqual((target.stat().st_dev, target.stat().st_ino), (replacement.st_dev, replacement.st_ino))
            self.assertEqual(target.read_bytes(), content)
            self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')
        else:
            self.assertEqual(self.git('branch', '--list'), '* main')

    def test_retained_anchor_fresh_inode_after_planning_refuses_before_publication(self):
        self.retained_anchor_replacement('planning')

    def test_retained_anchor_fresh_inode_after_private_commit_refuses_before_publication(self):
        self.retained_anchor_replacement('commit')

    def test_retained_anchor_fresh_inode_during_checkout_reports_recovery_branch(self):
        self.retained_anchor_replacement('checkout')

    @unittest.skipIf(os.name == 'nt', 'POSIX link and mode controls')
    def test_ignored_runtime_anchor_link_directory_and_mode_refuse(self):
        anchors, sentinel = self.stock_ignored_runtime()
        target = self.project/anchors[1]
        for kind in ('symlink', 'hardlink', 'directory', 'mode'):
            with self.subTest(kind=kind):
                target.unlink()
                if kind == 'symlink':
                    target.symlink_to(sentinel)
                elif kind == 'hardlink':
                    os.link(sentinel, target)
                elif kind == 'directory':
                    target.mkdir()
                else:
                    target.write_bytes(b'')
                    target.chmod(0o755)
                with self.assertRaises((upgrade.UpdateError, ValueError)):
                    self.update()
                self.assertEqual(self.git('branch', '--list'), '* main')
                self.assertEqual(sentinel.read_bytes(), b'ignored user data\x00\xff')
                if target.is_dir():
                    target.rmdir()
                else:
                    target.unlink()
                target.write_bytes(b'')

    def test_actual_stable_upgrade_preserves_selection_user_files_and_rollback(self):
        settings = (self.project / '.qwen/settings.json').read_bytes()
        self.update()
        self.assertNotEqual(self.git('rev-parse', 'HEAD'), self.before)
        self.assertEqual(self.git('rev-parse', 'main'), self.before)
        self.assertEqual(read_state(self.project).require_selection(), ('qwen',))
        self.assertEqual((self.project / 'user.txt').read_text(), 'keep my work\n')
        self.assertEqual((self.project / '.qwen/settings.json').read_bytes(), settings)
        self.assertEqual((self.project / 'scripts/getzilla_route.py').read_bytes(),
                         (ROOT / 'scripts/getzilla_route.py').read_bytes())
        self.assertEqual((self.project / '.getzilla/config/install-baseline-v2.3.0.json').read_bytes(),
                         (ROOT / '.getzilla/config/install-baseline-v2.3.0.json').read_bytes())
        self.git('switch', '--quiet', 'main')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.before)
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_candidate_bootstrap_commits_selection_before_existing_project_plan(self):
        from getzilla import platform_acceptance
        (self.project / MANIFEST).unlink()
        self.commit()
        plan = [sys.executable, str(ROOT/'scripts/install_into.py'), '--plan', str(self.project)]
        before = subprocess.run(plan, env=self.environment, capture_output=True, text=True, timeout=15)
        self.assertEqual(before.returncode, 2)
        self.assertIn('adapter selection is unresolved', before.stderr)

        def command(argv, *, cwd):
            self.run_process([str(a) for a in argv], cwd)
            return {'exit': 0}

        def installer(source, home, project, ref, *, create):
            self.assertFalse(create)
            self.assertEqual(self.git('status', '--porcelain'), '')
            after = subprocess.run(plan, env=self.environment, capture_output=True, text=True, timeout=15)
            self.assertEqual(after.returncode, 0, after.stderr)
            return {'exit': after.returncode}

        outcome = platform_acceptance.bootstrap_candidate(ROOT, self.project.parent/'candidate-home',
                                                          self.project, command, installer)
        self.assertEqual(outcome['exit'], 0)

    def test_restored_historical_vendor_bytes_match_actual_old_full_materializer(self):
        from getzilla.install_baseline import load_baseline, restore_release_payload
        actual = self.base/'actual-full-materializer'
        restored = self.base/'restored-old-artifact'
        self.run_process([sys.executable, str(self.source/'scripts/install_into.py'),
                          '--materialize-new', str(actual), '--full-layout'])
        result = restore_release_payload(ROOT, self.source, restored)
        self.assertEqual(result['baseline_mode'], 'restored-v230-artifact')
        self.assertEqual(result['vendor_files'], 695)
        for relative, proof in load_baseline(ROOT, 'v2.3.0').items():
            with self.subTest(path=relative):
                self.assertEqual((restored/relative).read_bytes(), (actual/relative).read_bytes())
                self.assertEqual(hashlib.sha256((restored/relative).read_bytes()).hexdigest(), proof['sha256'])
                self.assertTrue(mode_matches((restored/relative).stat().st_mode, proof['mode']))
        self.assertEqual((restored/'.getzilla/AGBP_SYNC.json').read_bytes(),
                         (actual/'.getzilla/AGBP_SYNC.json').read_bytes())
        self.assertFalse((restored/MANIFEST).exists())
        self.assertEqual({path.relative_to(restored).as_posix() for path in restored.rglob('*') if path.is_file()},
                         set(load_baseline(ROOT, 'v2.3.0')) | {'.getzilla/AGBP_SYNC.json'})
        self.run_process([sys.executable, str(self.source/'scripts/install_into.py'), '--plan', str(restored)])
        self.run_process(['git', 'init', '--quiet', '--initial-branch=main'], restored)
        user = restored/'user-settings.json'
        user.write_text('{"theme":"custom"}\n')
        (restored/'.gitignore').write_text('.getzilla/runtime/\n')
        self.run_process([sys.executable, str(ROOT/'scripts/getzilla_components.py'),
                          'adopt', '--agents', 'qwen'], restored)
        self.run_process(['git', 'add', '-A'], restored)
        self.run_process(['git', 'commit', '--quiet', '-m', 'Record restored release and explicit choice'], restored)
        self.assertEqual(self.run_process(['git', 'ls-files', '.getzilla/runtime'], restored), '')
        before = self.run_process(['git', 'rev-parse', 'HEAD'], restored)
        with mock.patch.dict(os.environ, self.environment):
            upgrade.sync_project(ROOT, restored, baseline_release='v2.3.0')
        self.assertEqual(read_state(restored).require_selection(), ('qwen',))
        self.assertEqual(user.read_text(), '{"theme":"custom"}\n')
        self.assertEqual((restored/'scripts/getzilla_route.py').read_bytes(), (ROOT/'scripts/getzilla_route.py').read_bytes())
        self.assertEqual(self.run_process(['git', 'rev-parse', 'main'], restored), before)
        self.run_process(['git', 'switch', '--quiet', 'main'], restored)
        self.assertEqual(self.run_process(['git', 'status', '--porcelain'], restored), '')

    def test_historical_restore_refuses_modified_source_and_existing_user_target(self):
        from getzilla.install_baseline import restore_release_payload
        target = self.base/'refused-existing-user-project'
        target.mkdir()
        user = target/'user.txt'
        user.write_text('user bytes remain\n')
        with self.assertRaises(ValueError):
            restore_release_payload(ROOT, self.source, target)
        self.assertEqual(user.read_text(), 'user bytes remain\n')
        source_file = self.source/'scripts/getzilla_route.py'
        original = source_file.read_bytes()
        try:
            source_file.write_bytes(original + b'\n# modified historical input\n')
            absent = self.base/'refused-real-modified-source'
            with self.assertRaisesRegex(ValueError, 'differs from qualified vendor bytes'):
                restore_release_payload(ROOT, self.source, absent)
            self.assertFalse(absent.exists())
        finally:
            source_file.write_bytes(original)
        with mock.patch('getzilla.install_baseline.load_baseline', return_value={
                'AGENTS.md': {'sha256': 'f'*64, 'mode': 0o644}}):
            absent = self.base/'refused-modified-source'
            with self.assertRaises(ValueError):
                restore_release_payload(ROOT, self.source, absent)
            self.assertFalse(absent.exists())

    def test_divergent_historical_file_refuses_before_publication(self):
        target = self.project / 'scripts/getzilla_route.py'
        target.write_text('# user customization\n')
        self.commit()
        before = self.git('rev-parse', 'HEAD')
        with self.assertRaisesRegex(upgrade.UpdateError, 'ownership conflict'):
            self.update()
        self.assertEqual(self.git('rev-parse', 'HEAD'), before)
        self.assertEqual(self.git('branch', '--list'), '* main')
        self.assertEqual(target.read_text(), '# user customization\n')

    def test_custom_read_only_policy_with_ledger_is_not_vendor_provenance(self):
        target = self.project / '.grok/config.toml'
        content = target.read_text().replace('workspace-write', 'read-only')
        self.assertIn('read-only', content)
        target.write_text(content)
        manifest = read_state(self.project).manifest
        record_owned(manifest, '.grok/config.toml', target.read_bytes(), 0o644)
        (self.project / MANIFEST).write_bytes(encode_manifest(manifest))
        self.commit()
        with self.assertRaisesRegex(upgrade.UpdateError, 'policy|baseline'):
            self.update()
        self.assertEqual(target.read_text(), content)
        self.assertEqual(self.git('branch', '--list'), '* main')

    def test_unknown_release_and_unsafe_combination_refuse_before_writes(self):
        for kwargs in ({'baseline_release': 'v0.0.0'},
                       {'baseline_release': 'v2.3.0', 'accept': True},
                       {'baseline_release': 'v2.3.0', 'retire': True}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(upgrade.UpdateError, 'baseline'):
                upgrade.sync_project(ROOT, self.project, **kwargs)
            self.assertEqual(self.git('rev-parse', 'HEAD'), self.before)
            self.assertEqual(self.git('status', '--porcelain'), '')

    @unittest.skipIf(os.name == 'nt', 'Windows modes use the existing write-bit semantics')
    def test_changed_historical_mode_refuses(self):
        target = self.project / 'scripts/getzilla_route.py'
        target.chmod(0o755 if target.stat().st_mode & 0o111 == 0 else 0o644)
        self.commit()
        with self.assertRaisesRegex(upgrade.UpdateError, 'ownership conflict'):
            self.update()
        self.assertEqual(self.git('branch', '--list'), '* main')

    def test_explicit_keep_and_unknown_file_survive(self):
        relative = 'scripts/getzilla_route.py'
        content = b'# explicitly retained custom implementation\n'
        (self.project / relative).write_bytes(content)
        record = {'schema_version': 1, 'kept_local': [relative],
                  'kept_local_sha256': {relative: hashlib.sha256(content).hexdigest()}}
        (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps(record))
        (self.project / '.qwen/private.txt').write_text('unknown user setting\n')
        self.commit()
        self.update()
        self.assertEqual((self.project / relative).read_bytes(), content)
        self.assertEqual((self.project / '.qwen/private.txt').read_text(), 'unknown user setting\n')
        self.assertNotIn(relative, read_state(self.project).manifest['components']['core']['owned'])

    def test_substituted_catalog_refuses_before_target_transaction(self):
        home = self.base / 'substituted-home'
        catalog = home / '.getzilla/config/install-baseline-v2.3.0.json'
        catalog.parent.mkdir(parents=True)
        catalog.write_bytes((ROOT / '.getzilla/config/install-baseline-v2.3.0.json').read_bytes() + b' ')
        with self.assertRaisesRegex(upgrade.UpdateError, 'catalog digest mismatch'):
            upgrade.sync_project(home, self.project, baseline_release='v2.3.0')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.before)
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_failed_private_commit_leaves_original_tree_and_branch(self):
        with mock.patch.object(upgrade, 'commit_changes', side_effect=upgrade.UpdateError('publication failed')):
            with self.assertRaisesRegex(upgrade.UpdateError, 'publication failed'):
                self.update()
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.before)
        self.assertEqual(self.git('status', '--porcelain'), '')
        self.assertEqual(self.git('branch', '--list'), '* main')

    def test_cli_rejects_baseline_with_tool_dispatch_or_self_update(self):
        for args in (['tools', '--baseline-release', 'v2.3.0'],
                     ['--only', 'opengrep', '--baseline-release', 'v2.3.0'],
                     ['--baseline-release', 'v2.3.0']):
            with contextlib.redirect_stderr(io.StringIO()), \
                    mock.patch.object(upgrade, 'run_tools', side_effect=AssertionError('tool dispatch forbidden')), \
                    mock.patch.object(upgrade, 'update_self', side_effect=AssertionError('self update forbidden')):
                with self.assertRaises(SystemExit) as caught:
                    upgrade.main(args)
                self.assertEqual(caught.exception.code, 2)
            self.assertEqual(self.git('rev-parse', 'HEAD'), self.before)
