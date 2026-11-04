"""`getzilla update`: the project sync writes managed files on a new branch, never over local work."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / '.getzilla'))

import getzilla_upgrade as upgrade  # noqa: E402

GIT_ENV = {'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.invalid',
           'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.invalid'}


def git(project: Path, *args: str) -> str:
    return subprocess.run(['git', '-C', str(project), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


class ProjectSyncTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.dict(os.environ, {**GIT_ENV, 'GETZILLA_AGENT': 'claude'})
        patcher.start()
        self.addCleanup(patcher.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.project = Path(tmp.name).resolve() / 'project'
        (self.project / '.getzilla').mkdir(parents=True)
        from getzilla.component_state import MANIFEST, V2, encode_manifest
        (self.project / MANIFEST).write_bytes(encode_manifest({'schema_version': V2, 'agents': ['claude'], 'components': {}}))
        (self.project / '.getzilla/runtime').mkdir()
        (self.project / '.getzilla/runtime/.gitignore').write_bytes((ROOT / '.getzilla/runtime/.gitignore').read_bytes())
        (self.project / 'ruff.toml').write_text('line-length = 80\n', encoding='utf-8')
        (self.project / 'AGENTS.md').write_text('# Project rules\n\nKeep this.\n', encoding='utf-8')
        git(self.project, 'init', '--quiet', '--initial-branch=main')
        self.commit('initial')

    def commit(self, message: str) -> None:
        git(self.project, 'add', '-A')
        git(self.project, 'commit', '--quiet', '-m', message)

    def select(self, agents: tuple[str, ...]) -> dict:
        from getzilla.component_state import MANIFEST, V2, encode_manifest
        manifest = {'schema_version': V2, 'agents': list(agents), 'components': {}}
        (self.project / MANIFEST).write_bytes(encode_manifest(manifest))
        return manifest

    def test_empty_selection_keeps_unselected_custom_files_and_records_target_ownership(self) -> None:
        from getzilla.component_state import read_state
        self.select(())
        (self.project / '.codex').mkdir()
        (self.project / '.codex/custom.txt').write_text('user file')
        self.commit('explicit empty selection')
        with mock.patch.dict(os.environ, {'GETZILLA_AGENT': 'codex'}):
            upgrade.sync_project(ROOT, self.project)
        state = read_state(self.project)
        self.assertEqual(state.require_selection(), ())
        self.assertIn('scripts/getzilla_route.py', state.manifest['components']['core']['owned'])
        self.assertFalse((self.project / '.codex/hooks.json').exists())
        self.assertFalse((self.project / '.claude').exists())
        self.assertEqual((self.project / '.codex/custom.txt').read_text(), 'user file')

    def test_unknown_custom_managed_file_refuses_without_new_branch(self) -> None:
        target = self.project / 'scripts/getzilla_route.py'
        target.parent.mkdir()
        target.write_text('# custom route implementation\n')
        self.commit('custom managed path')
        before = git(self.project, 'rev-parse', 'HEAD')
        with self.assertRaisesRegex(upgrade.UpdateError, 'conflict'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), before)
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')
        self.assertEqual(target.read_text(), '# custom route implementation\n')

    def test_owned_old_file_upgrades_with_its_proof_in_the_same_commit(self) -> None:
        from getzilla.component_state import MANIFEST, encode_manifest, read_state, record_owned
        manifest = self.select(('claude',))
        target = self.project / 'scripts/getzilla_route.py'
        target.parent.mkdir()
        target.write_bytes(b'# old managed route\n')
        os.chmod(target, 0o644)
        record_owned(manifest, 'scripts/getzilla_route.py', target.read_bytes(), 0o644)
        (self.project / MANIFEST).write_bytes(encode_manifest(manifest))
        self.commit('record an older managed version')
        upgrade.sync_project(ROOT, self.project)
        current = read_state(self.project).manifest['components']['core']['owned']['scripts/getzilla_route.py']
        self.assertEqual(current['sha256'], hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual(target.read_bytes(), (ROOT / 'scripts/getzilla_route.py').read_bytes())

    def test_ignored_uncommitted_selection_cannot_authorize_an_update(self) -> None:
        from getzilla.component_state import MANIFEST
        git(self.project, 'rm', '--cached', '--quiet', MANIFEST)
        (self.project / '.gitignore').write_text(MANIFEST + '\n')
        self.commit('selection is not committed')
        with self.assertRaisesRegex(upgrade.UpdateError, 'committed'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')

    def test_codex_update_preserves_canonical_overlay_and_custom_enabled_configuration(self) -> None:
        self.select(('codex',))
        overlay = {'hooks': {'Stop': [{'hooks': [{'type': 'command', 'command': 'echo user-stop'}]}]}}
        (self.project / '.getzilla/config').mkdir(parents=True, exist_ok=True)
        overlay_path = self.project / '.getzilla/config/codex-hooks.json'
        overlay_path.write_text(json.dumps(overlay))
        (self.project / '.codex').mkdir()
        config = self.project / '.codex/config.toml'
        config.write_bytes(b'[features]\ncodex_hooks = true\n[custom]\nkeep = true\n')
        saved_overlay, saved_config = overlay_path.read_bytes(), config.read_bytes()
        self.commit('custom Codex overlay and settings')
        upgrade.sync_project(ROOT, self.project)
        self.assertEqual(overlay_path.read_bytes(), saved_overlay)
        self.assertEqual(config.read_bytes(), saved_config)
        hooks = json.loads((self.project / '.codex/hooks.json').read_text())['hooks']['Stop']
        self.assertIn('stop_gate.py', hooks[0]['hooks'][0]['command'])
        self.assertEqual(hooks[1:], overlay['hooks']['Stop'])

    def test_neutral_upgrade_preserves_legacy_overlay_and_retires_only_proven_sources(self) -> None:
        from getzilla.component_state import MANIFEST, encode_manifest, record_owned, read_state
        manifest = self.select(('codex',))
        overlay = b'{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"entire hooks codex stop"}]}]}}\n'
        sources = {'.grok/hooks/pre_tool_use.py': b'# previous managed guard\n',
                   '.grok/agents/code_reviewer.toml': b'# previous role\n',
                   '.grok/codex-hooks.json': overlay}
        for path, content in sources.items():
            target = self.project / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o644)
            record_owned(manifest, path, content, 0o644)
        # These files have no valid ownership proof and must survive the migration.
        custom = self.project / '.grok/hooks/custom.py'
        custom.write_bytes(b'# user hook\n')
        # Pre-neutral installs classified these shared sources as Core.
        old = manifest['components'].pop('agent:grok')
        manifest['components']['core'] = old
        (self.project / MANIFEST).write_bytes(encode_manifest(manifest))
        self.commit('legacy common sources with proof')
        original = git(self.project, 'rev-parse', 'HEAD')
        upgrade.sync_project(ROOT, self.project)
        self.assertEqual((self.project / '.getzilla/config/codex-hooks.json').read_bytes(), overlay)
        migrated = read_state(self.project).manifest['components']['core']
        self.assertIn('.getzilla/config/codex-hooks.json', migrated['files'])
        self.assertNotIn('.getzilla/config/codex-hooks.json', migrated['owned'])
        for path in sources:
            self.assertFalse((self.project / path).exists(), path)
        self.assertEqual(custom.read_bytes(), b'# user hook\n')
        hooks = json.loads((self.project / '.codex/hooks.json').read_bytes())['hooks']['Stop']
        self.assertIn('.getzilla/hooks/stop_gate.py', hooks[0]['hooks'][0]['command'])
        self.assertEqual(hooks[1]['hooks'][0]['command'], 'entire hooks codex stop')
        self.assertNotIn('.grok/hooks/pre_tool_use.py', read_state(self.project).manifest['components']['core']['files'])
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD^'), original)
        current = git(self.project, 'rev-parse', 'HEAD')
        planned = upgrade.planned_changes(upgrade.load_installer(ROOT), ROOT, self.project)
        self.assertEqual([path for path, _, _ in planned], [])
        upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), current)
        git(self.project, 'switch', '--quiet', 'main')
        self.assertEqual((self.project / '.grok/hooks/pre_tool_use.py').read_bytes(), sources['.grok/hooks/pre_tool_use.py'])
        self.assertFalse((self.project / '.getzilla/hooks/pre_tool_use.py').exists())

    def test_custom_legacy_canonical_guard_refuses_without_publication(self) -> None:
        from getzilla.component_state import MANIFEST, encode_manifest
        relative = '.grok/hooks/pre_tool_use.py'
        target = self.project / relative
        for scenario in ('changed', 'unowned', 'kept'):
            with self.subTest(scenario=scenario):
                manifest = self.select(('codex',))
                target.parent.mkdir(parents=True, exist_ok=True)
                current = b'# consumer-specific policy\n'
                target.write_bytes(current)
                target.chmod(0o644)
                if scenario != 'unowned':
                    baseline = b'# managed baseline\n' if scenario == 'changed' else current
                    manifest['components']['core'] = {'files': [relative], 'owned': {
                        relative: {'sha256': hashlib.sha256(baseline).hexdigest(), 'mode': 0o644}}}
                if scenario == 'kept':
                    (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
                        'schema_version': 1, 'kept_local': [relative],
                        'kept_local_sha256': {relative: hashlib.sha256(current).hexdigest()}}))
                (self.project / MANIFEST).write_bytes(encode_manifest(manifest))
                self.commit('custom legacy guard ' + scenario)
                original = git(self.project, 'rev-parse', 'HEAD')
                with self.assertRaisesRegex(upgrade.UpdateError, 'legacy hook.*reconciled'):
                    upgrade.sync_project(ROOT, self.project)
                self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), original)
                self.assertEqual(git(self.project, 'branch', '--show-current'), 'main')
                self.assertEqual(target.read_bytes(), current)
                self.assertFalse((self.project / '.getzilla/hooks/pre_tool_use.py').exists())

    def test_unselected_custom_adapter_keeps_legacy_guard_dependency(self) -> None:
        from getzilla.component_state import MANIFEST, encode_manifest, record_owned
        manifest = self.select(('codex',))
        relative = '.grok/hooks/pre_tool_use.py'
        hook = self.project / relative
        hook.parent.mkdir(parents=True)
        content = b'# baseline used by a custom unselected adapter\n'
        hook.write_bytes(content)
        hook.chmod(0o644)
        record_owned(manifest, relative, content, 0o644)
        # A custom unselected adapter can still depend on the previous launcher.
        config = self.project / '.claude/settings.json'
        config.parent.mkdir()
        custom = json.dumps({'hooks': {'PreToolUse': [{'hooks': [{'command': 'python3 ' + relative}]}]}}).encode()
        config.write_bytes(custom)
        (self.project / MANIFEST).write_bytes(encode_manifest(manifest))
        self.commit('custom adapter depends on legacy hook')
        upgrade.sync_project(ROOT, self.project)
        self.assertEqual(config.read_bytes(), custom)
        self.assertEqual(hook.read_bytes(), content)
        self.assertTrue((self.project / '.getzilla/hooks/pre_tool_use.py').exists())
        self.assertIn('.getzilla/hooks/pre_tool_use.py', (self.project / '.codex/hooks.json').read_text())

    def _selected_kept_legacy_dependency(self, agent, config_path, *, legacy_record=False, keep_alias=None):
        from getzilla.component_state import MANIFEST, encode_manifest, record_owned
        manifest = self.select((agent,))
        relative = '.grok/hooks/pre_tool_use.py'
        hook = self.project / relative
        hook.parent.mkdir(parents=True)
        content = b'# baseline used by a kept selected adapter\n'
        hook.write_bytes(content)
        hook.chmod(0o644)
        record_owned(manifest, relative, content, 0o644)
        config = self.project / config_path
        config.parent.mkdir(exist_ok=True, parents=True)
        custom = json.dumps({'hooks': {'PreToolUse': [{'hooks': [{'command': 'python3 ' + relative}]}]}}).encode()
        config.write_bytes(custom)
        record_path = '.grok-stack/AGBP_SYNC.json' if legacy_record else '.getzilla/AGBP_SYNC.json'
        record = self.project / record_path
        record.parent.mkdir(exist_ok=True, parents=True)
        kept = keep_alias or config_path
        record.write_text(json.dumps({'schema_version': 1, 'kept_local': [kept],
                                      'kept_local_sha256': {kept: hashlib.sha256(custom).hexdigest()}}))
        (self.project / MANIFEST).write_bytes(encode_manifest(manifest))
        self.commit('selected kept adapter depends on legacy hook')
        upgrade.sync_project(ROOT, self.project)
        self.assertEqual(config.read_bytes(), custom)
        self.assertTrue(hook.is_file(), 'a kept selected adapter still references this guard')
        self.assertEqual(hook.read_bytes(), content)
        self.assertTrue((self.project / '.getzilla/hooks/pre_tool_use.py').exists())
        before = git(self.project, 'rev-parse', 'HEAD')
        self.assertIn('up to date', upgrade.sync_project(ROOT, self.project))
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), before)

    def test_selected_kept_claude_retains_legacy_guard_dependency(self) -> None:
        self._selected_kept_legacy_dependency('claude', '.claude/settings.json')

    def test_selected_kept_adapter_aliases_retain_legacy_guard_dependencies(self) -> None:
        from contextlib import ExitStack
        from types import SimpleNamespace
        from getzilla import component_state
        original_project = self.project
        original_match = component_state.match_kept_local
        def windows_match(*args):
            # Exercise the real Windows case matcher with the native host's I/O backend.
            with mock.patch.object(component_state, 'fsx', SimpleNamespace(WINDOWS=True)):
                return original_match(*args)
        cases = [('qwen', '.qwen/settings.json', False, None),
                 ('gemini', '.gemini/settings.json', False, None),
                 ('copilot', '.github/hooks/getzilla.json', False, None),
                 ('grok', '.grok/hooks.json', False, None),
                 ('claude', '.claude/settings.json', True, None),
                 ('claude', '.claude/settings.json', False, '.CLAUDE/SETTINGS.JSON')]
        with tempfile.TemporaryDirectory() as tmp:
            try:
                for index, (agent, path, legacy, alias) in enumerate(cases):
                    with self.subTest(agent=agent, legacy=legacy, alias=alias), ExitStack() as stack:
                        target = Path(tmp) / str(index)
                        git(original_project, 'clone', '--quiet', str(original_project), str(target))
                        self.project = target
                        if alias is not None:
                            installer = upgrade.load_installer(ROOT)
                            stack.enter_context(mock.patch.object(upgrade, 'load_installer', return_value=installer))
                            stack.enter_context(mock.patch.object(upgrade, 'match_kept_local', side_effect=windows_match))
                            stack.enter_context(mock.patch.object(installer, 'match_kept_local', side_effect=windows_match))
                        self._selected_kept_legacy_dependency(agent, path, legacy_record=legacy, keep_alias=alias)
            finally:
                self.project = original_project

    def test_migrated_codex_overlay_retains_legacy_guard_dependency(self) -> None:
        from getzilla.component_state import MANIFEST, encode_manifest, record_owned
        manifest = self.select(('codex',))
        path = '.grok/hooks/post_tool_use.py'
        target = self.project / path
        target.parent.mkdir(parents=True)
        content = b'# baseline used by a retained overlay\n'
        target.write_bytes(content)
        target.chmod(0o644)
        record_owned(manifest, path, content, 0o644)
        overlay = {'hooks': {'Stop': [{'hooks': [{'command': 'python3 ' + path}]}]}}
        (self.project / '.grok/codex-hooks.json').write_text(json.dumps(overlay))
        (self.project / MANIFEST).write_bytes(encode_manifest(manifest))
        self.commit('overlay still calls a legacy guard')
        upgrade.sync_project(ROOT, self.project)
        self.assertEqual(target.read_bytes(), content)
        hooks = json.loads((self.project / '.codex/hooks.json').read_bytes())['hooks']['Stop']
        self.assertIn('.getzilla/hooks/stop_gate.py', hooks[0]['hooks'][0]['command'])
        self.assertEqual(hooks[1]['hooks'][0]['command'], 'python3 ' + path)

    def test_head_change_during_planning_refuses_before_branch_publication(self) -> None:
        original = upgrade.planned_changes
        def moving(*args, **kwargs):
            result = original(*args, **kwargs)
            git(self.project, 'commit', '--allow-empty', '--quiet', '-m', 'concurrent commit')
            return result
        with mock.patch.object(upgrade, 'planned_changes', side_effect=moving):
            with self.assertRaisesRegex(upgrade.UpdateError, 'changed'):
                upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')
        self.assertFalse((self.project / 'scripts').exists())

    def test_changed_files_after_checkout_report_the_retained_branch_as_incomplete(self) -> None:
        original = upgrade.git
        def changed_after_switch(project, *args, **kwargs):
            result = original(project, *args, **kwargs)
            if args[0] == 'switch' and result.returncode == 0:
                (project / 'scripts/getzilla_route.py').write_text('# changed after checkout\n')
            return result
        with mock.patch.object(upgrade, 'git', side_effect=changed_after_switch):
            with self.assertRaisesRegex(upgrade.UpdateError, 'retained.*incomplete'):
                upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'branch', '--show-current'), upgrade.BRANCH_PREFIX + upgrade.version_of(ROOT))
        self.assertEqual((self.project / 'scripts/getzilla_route.py').read_text(), '# changed after checkout\n')

    def test_manifest_changed_after_checkout_is_detected_even_when_git_status_is_clean(self) -> None:
        from getzilla.component_state import MANIFEST
        original = upgrade.git
        def changed_after_switch(project, *args, **kwargs):
            result = original(project, *args, **kwargs)
            if args[0] == 'switch' and result.returncode == 0:
                git(project, 'update-index', '--skip-worktree', MANIFEST)
                manifest = json.loads((project / MANIFEST).read_bytes())
                manifest['agents'] = []
                (project / MANIFEST).write_text(json.dumps(manifest))
            return result
        with mock.patch.object(upgrade, 'git', side_effect=changed_after_switch):
            with self.assertRaisesRegex(upgrade.UpdateError, 'retained.*incomplete'):
                upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'status', '--porcelain'), '')
        self.assertEqual(json.loads((self.project / MANIFEST).read_bytes())['agents'], [])

    def test_branch_changed_after_checkout_is_detected_even_at_the_same_commit(self) -> None:
        original = upgrade.git
        def changed_after_switch(project, *args, **kwargs):
            result = original(project, *args, **kwargs)
            if args[0] == 'switch' and result.returncode == 0:
                git(project, 'switch', '--quiet', '-c', 'post-checkout')
            return result
        with mock.patch.object(upgrade, 'git', side_effect=changed_after_switch):
            with self.assertRaisesRegex(upgrade.UpdateError, 'retained.*incomplete'):
                upgrade.sync_project(ROOT, self.project)
        branch = upgrade.BRANCH_PREFIX + upgrade.version_of(ROOT)
        self.assertEqual(git(self.project, 'branch', '--show-current'), 'post-checkout')
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), git(self.project, 'rev-parse', branch))

    def test_sync_commits_on_a_new_branch_and_is_idempotent(self) -> None:
        result = upgrade.sync_project(ROOT, self.project)
        branch = upgrade.BRANCH_PREFIX + upgrade.version_of(ROOT)
        self.assertIn(branch, result)
        self.assertEqual(git(self.project, 'branch', '--show-current'), branch)
        self.assertEqual(git(self.project, 'status', '--porcelain'), '')
        self.assertEqual(git(self.project, 'rev-list', '--count', 'main'), '1')
        self.assertEqual((self.project / 'scripts/getzilla_route.py').read_bytes(),
                         (ROOT / 'scripts/getzilla_route.py').read_bytes())
        agents = (self.project / 'AGENTS.md').read_text(encoding='utf-8')
        self.assertTrue(agents.startswith('# Project rules\n\nKeep this.\n'))
        self.assertEqual(agents.count('<!-- ADAPTIVE-GROK-PRO:START -->'), 1)
        head = git(self.project, 'rev-parse', 'HEAD')
        self.assertIn('up to date', upgrade.sync_project(ROOT, self.project))
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), head)

    def test_uncommitted_changes_stop_the_sync(self) -> None:
        (self.project / 'notes.txt').write_text('work in progress\n', encoding='utf-8')
        with self.assertRaisesRegex(upgrade.UpdateError, 'uncommitted changes'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'branch', '--show-current'), 'main')
        self.assertFalse((self.project / 'scripts').exists())

    def test_kept_local_paths_are_left_alone(self) -> None:
        local = (self.project / 'ruff.toml').read_bytes()
        record = {'schema_version': 1, 'kept_local': ['ruff.toml'],
                  'kept_local_sha256': {'ruff.toml': hashlib.sha256(local).hexdigest()}}
        (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps(record), encoding='utf-8')
        self.commit('keep ruff.toml')
        upgrade.sync_project(ROOT, self.project)
        self.assertEqual((self.project / 'ruff.toml').read_bytes(), local)

    def test_kept_manifest_refuses_update_before_files_or_new_branch(self) -> None:
        from getzilla.component_state import MANIFEST
        original = (self.project / MANIFEST).read_bytes()
        relative = '.GETZILLA/MANAGED-COMPONENTS.JSON' if os.name == 'nt' else MANIFEST
        (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': [relative],
            'kept_local_sha256': {relative: hashlib.sha256(original).hexdigest()},
        }))
        self.commit('keep target component state')
        head = git(self.project, 'rev-parse', 'HEAD')
        with self.assertRaisesRegex(upgrade.UpdateError, 'kept.*manifest'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), head)
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')
        self.assertEqual((self.project / MANIFEST).read_bytes(), original)
        self.assertFalse((self.project / 'scripts').exists())

    def test_kept_manifest_allows_an_already_current_update(self) -> None:
        from getzilla.component_state import MANIFEST
        upgrade.sync_project(ROOT, self.project)
        manifest = (self.project / MANIFEST).read_bytes()
        (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': [MANIFEST],
            'kept_local_sha256': {MANIFEST: hashlib.sha256(manifest).hexdigest()},
        }))
        self.commit('keep current target component state')
        before = git(self.project, 'rev-parse', 'HEAD')
        self.assertIn('up to date', upgrade.sync_project(ROOT, self.project))
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), before)
        self.assertEqual((self.project / MANIFEST).read_bytes(), manifest)

    def test_kept_manifest_also_fences_final_migration_ownership_changes(self) -> None:
        from getzilla.component_state import MANIFEST
        upgrade.sync_project(ROOT, self.project)
        git(self.project, 'branch', '-m', 'installed')
        manifest = (self.project / MANIFEST).read_bytes()
        (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': [MANIFEST],
            'kept_local_sha256': {MANIFEST: hashlib.sha256(manifest).hexdigest()},
        }))
        (self.project / '.grok-stack').mkdir()
        (self.project / '.grok-stack/AGBP_SYNC.log.jsonl').write_bytes(b'{"old": "history"}\n')
        self.commit('retain state before legacy log migration')
        before = git(self.project, 'rev-parse', 'HEAD')
        self.assertEqual(upgrade.planned_changes(upgrade.load_installer(ROOT), ROOT, self.project), [])
        with self.assertRaisesRegex(upgrade.UpdateError, 'kept.*manifest'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), before)
        self.assertEqual(git(self.project, 'branch', '--show-current'), 'installed')
        self.assertEqual(git(self.project, 'branch', '--list', upgrade.BRANCH_PREFIX + upgrade.version_of(ROOT)), '')
        self.assertEqual((self.project / MANIFEST).read_bytes(), manifest)
        self.assertFalse((self.project / '.getzilla/AGBP_SYNC.log.jsonl').exists())

    def test_kept_paths_drop_owned_proofs_and_retain_history_on_repeated_update(self) -> None:
        from getzilla.component_state import MANIFEST, encode_manifest, read_state, record_owned
        manifest = self.select(())
        contents = {'scripts/getzilla_route.py': b'# retained route\n',
                    '.codex/hooks.json': b'{"user": "unselected hooks"}\n'}
        for path, content in contents.items():
            target = self.project / path
            target.parent.mkdir(parents=True)
            target.write_bytes(content)
            os.chmod(target, 0o644)
            record_owned(manifest, path, content, 0o644)
        (self.project / MANIFEST).write_bytes(encode_manifest(manifest))
        (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': list(contents),
            'kept_local_sha256': {path: hashlib.sha256(content).hexdigest() for path, content in contents.items()},
        }))
        self.commit('retain formerly owned files')
        for _ in range(2):
            upgrade.sync_project(ROOT, self.project)
            records = read_state(self.project).manifest['components']
            for path, content in contents.items():
                self.assertEqual((self.project / path).read_bytes(), content)
                self.assertTrue(any(path in record['files'] for record in records.values()))
                self.assertFalse(any(path in record.get('owned', {}) for record in records.values()))

    def test_kept_codex_config_refuses_missing_hooks_before_branch_publication(self) -> None:
        self.select(('codex',))
        (self.project / '.codex').mkdir()
        content = (ROOT / '.codex/config.toml').read_bytes()
        (self.project / '.codex/config.toml').write_bytes(content)
        (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': ['.codex/config.toml'],
            'kept_local_sha256': {'.codex/config.toml': hashlib.sha256(content).hexdigest()},
        }))
        self.commit('keep Codex config without hooks')
        before = git(self.project, 'rev-parse', 'HEAD')
        with self.assertRaisesRegex(upgrade.UpdateError, 'Codex'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), before)
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')
        self.assertFalse((self.project / '.codex/hooks.json').exists())

    def test_kept_codex_pair_is_preserved_without_owned_proofs(self) -> None:
        from getzilla.component_state import MANIFEST, encode_manifest, read_state, record_owned
        manifest = self.select(('codex',))
        installer = upgrade.load_installer(ROOT)
        payload = {entry.path: entry for entry in installer.build_payload(ROOT, selection=installer.PayloadSelection(('codex',)))}
        pair = ('.codex/hooks.json', '.codex/config.toml')
        (self.project / '.codex').mkdir()
        for path in pair:
            (self.project / path).write_bytes(payload[path].content)
            os.chmod(self.project / path, payload[path].mode)
            record_owned(manifest, path, payload[path].content, payload[path].mode)
        (self.project / MANIFEST).write_bytes(encode_manifest(manifest))
        (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': list(pair),
            'kept_local_sha256': {path: hashlib.sha256(payload[path].content).hexdigest() for path in pair},
        }))
        self.commit('keep coherent Codex activation')
        upgrade.sync_project(ROOT, self.project)
        owned = read_state(self.project).manifest['components']['agent:codex']['owned']
        for path in pair:
            self.assertEqual((self.project / path).read_bytes(), payload[path].content)
            self.assertNotIn(path, owned)

    def test_kept_sync_log_cannot_be_created_by_the_legacy_migration(self) -> None:
        path = '.getzilla/AGBP_SYNC.log.jsonl'
        (self.project / '.grok-stack').mkdir()
        (self.project / '.grok-stack/AGBP_SYNC.log.jsonl').write_bytes(b'{"sync": 1}\n')
        (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps({
            'schema_version': 1, 'kept_local': [path], 'kept_local_sha256': {},
        }))
        self.commit('keep the new log absent')
        before = git(self.project, 'rev-parse', 'HEAD')
        with self.assertRaisesRegex(upgrade.UpdateError, 'kept'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), before)
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')
        self.assertFalse((self.project / path).exists())

    def test_accept_local_records_the_current_digest_of_a_changed_kept_file(self) -> None:
        old = (self.project / 'AGENTS.md').read_bytes()
        record = {'schema_version': 1, 'kept_local': ['AGENTS.md'],
                  'kept_local_sha256': {'AGENTS.md': hashlib.sha256(old).hexdigest()}}
        (self.project / '.getzilla/AGBP_SYNC.json').write_text(json.dumps(record), encoding='utf-8')
        self.commit('keep AGENTS.md')
        (self.project / 'AGENTS.md').write_text('# Project rules, edited later\n', encoding='utf-8')
        self.commit('edit AGENTS.md')
        with self.assertRaisesRegex(upgrade.UpdateError, '--accept-local'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')
        result = upgrade.sync_project(ROOT, self.project, accept=True)
        self.assertIn('kept your current AGENTS.md', result)
        self.assertEqual((self.project / 'AGENTS.md').read_text(encoding='utf-8'), '# Project rules, edited later\n')
        saved = json.loads((self.project / '.getzilla/AGBP_SYNC.json').read_text(encoding='utf-8'))
        self.assertEqual(saved['kept_local_sha256']['AGENTS.md'],
                         hashlib.sha256(b'# Project rules, edited later\n').hexdigest())
        self.assertEqual(saved['kept_local'], ['AGENTS.md'])
        self.assertEqual(git(self.project, 'status', '--porcelain'), '')

    def test_existing_update_branch_is_not_reused(self) -> None:
        git(self.project, 'branch', upgrade.BRANCH_PREFIX + upgrade.version_of(ROOT))
        with self.assertRaisesRegex(upgrade.UpdateError, 'already exists'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'branch', '--show-current'), 'main')

    def test_a_failure_before_the_branch_leaves_the_project_unchanged(self) -> None:
        real = upgrade._git_out

        def failing(cwd, *args, **kwargs):
            if args[0] == 'commit-tree':
                raise upgrade.UpdateError('simulated commit failure')
            return real(cwd, *args, **kwargs)

        with mock.patch.object(upgrade, '_git_out', side_effect=failing):
            with self.assertRaisesRegex(upgrade.UpdateError, 'simulated'):
                upgrade.sync_project(ROOT, self.project)
        self.assertEqual(git(self.project, 'branch', '--show-current'), 'main')
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')
        self.assertEqual(git(self.project, 'status', '--porcelain'), '')

    @unittest.skipIf(os.name == 'nt', 'POSIX symlinks')
    def test_a_committed_link_is_never_written_through(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            (self.project / 'scripts').symlink_to(outside)
            self.commit('link scripts')
            with self.assertRaises(upgrade.UpdateError):
                upgrade.sync_project(ROOT, self.project)
            self.assertEqual(os.listdir(outside), [])
        self.assertEqual(git(self.project, 'branch', '--show-current'), 'main')

    def test_an_ignored_local_file_on_a_managed_path_is_never_overwritten(self) -> None:
        (self.project / '.gitignore').write_text('bandit.yaml\n', encoding='utf-8')
        self.commit('ignore bandit.yaml')
        (self.project / 'bandit.yaml').write_text('mine\n', encoding='utf-8')
        with self.assertRaisesRegex(upgrade.UpdateError, 'bandit.yaml'):
            upgrade.sync_project(ROOT, self.project)
        self.assertEqual((self.project / 'bandit.yaml').read_text(encoding='utf-8'), 'mine\n')
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')

    def test_a_subfolder_is_not_a_repository_root(self) -> None:
        (self.project / 'sub/.getzilla').mkdir(parents=True)
        with self.assertRaisesRegex(upgrade.UpdateError, 'not the root'):
            upgrade.sync_project(ROOT, self.project / 'sub')

    def test_the_projects_own_lint_configuration_stays_and_a_sync_record_appears(self) -> None:
        result = upgrade.sync_project(ROOT, self.project)
        self.assertEqual((self.project / 'ruff.toml').read_text(encoding='utf-8'), 'line-length = 80\n')
        self.assertIn('kept your own ruff.toml', result)
        self.assertEqual((self.project / 'bandit.yaml').read_bytes(), (ROOT / 'bandit.yaml').read_bytes())
        self.assertEqual(json.loads((self.project / '.getzilla/AGBP_SYNC.json').read_text(encoding='utf-8')),
                         {'kept_local': [], 'kept_local_sha256': {}, 'schema_version': 1})
        self.assertIn('new executable file(s) arrive', result)

    def _pre_rename(self) -> None:
        for rel in ('.grok-stack/adaptive_grok/verification.py', 'scripts/grok_route.py'):
            (self.project / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.project / rel).write_text('old = 1\n', encoding='utf-8')
        digest = hashlib.sha256(b'line-length = 80\n').hexdigest()
        record = {'schema_version': 1, 'kept_local': ['ruff.toml'], 'kept_local_sha256': {'ruff.toml': digest}}
        (self.project / '.grok-stack/AGBP_SYNC.json').write_text(json.dumps(record), encoding='utf-8')
        self.commit('pre-rename layout')

    def test_a_pre_rename_project_gets_its_record_moved_and_its_old_files_listed(self) -> None:
        self._pre_rename()
        result = upgrade.sync_project(ROOT, self.project)
        record = json.loads((self.project / '.getzilla/AGBP_SYNC.json').read_text(encoding='utf-8'))
        self.assertEqual(record['kept_local'], ['ruff.toml'])
        self.assertIn('pre-rename file(s) remain', result)
        self.assertIn('--retire-legacy', result)
        self.assertTrue((self.project / 'scripts/grok_route.py').is_file())

    def test_retire_legacy_removes_the_old_files_in_the_same_commit(self) -> None:
        self._pre_rename()
        result = upgrade.sync_project(ROOT, self.project, retire=True)
        self.assertIn('removed', result)
        self.assertFalse((self.project / '.grok-stack').exists())
        self.assertFalse((self.project / 'scripts/grok_route.py').exists())
        self.assertEqual(git(self.project, 'status', '--porcelain'), '')
        self.assertEqual(git(self.project, 'rev-list', '--count', 'HEAD'), '3')

    def test_retire_legacy_keeps_old_files_that_have_no_replacement(self) -> None:
        # A vendored factory under its old name is live code when the update installs no new factory.
        self._pre_rename()
        (self.project / 'factory/src/adaptive_factory').mkdir(parents=True)
        (self.project / 'factory/src/adaptive_factory/cli.py').write_text('live = 1\n', encoding='utf-8')
        (self.project / '.grok-stack/AGBP_SYNC.log.jsonl').write_text('{"sync": 1}\n', encoding='utf-8')
        self.commit('vendored factory and sync log')
        result = upgrade.sync_project(ROOT, self.project, retire=True)
        self.assertTrue((self.project / 'factory/src/adaptive_factory/cli.py').is_file())
        self.assertIn('no Getzilla replacement', result)
        self.assertFalse((self.project / '.grok-stack').exists())
        self.assertEqual((self.project / '.getzilla/AGBP_SYNC.log.jsonl').read_text(encoding='utf-8'), '{"sync": 1}\n')

    def test_retirement_relies_on_the_engine_archive_and_a_log_already_moved(self) -> None:
        # #215: the old engine module is replaced by the engine archive, not a module file, and a sync
        # log already committed at the new path is kept as it is.
        self._pre_rename()
        (self.project / '.grok-stack/AGBP_SYNC.log.jsonl').write_text('{"old": 1}\n', encoding='utf-8')
        (self.project / '.getzilla/AGBP_SYNC.log.jsonl').write_text('{"new": 1}\n', encoding='utf-8')
        self.commit('sync log at both paths')
        upgrade.sync_project(ROOT, self.project, retire=True)
        self.assertTrue((self.project / '.getzilla/getzilla.zip').is_file())
        self.assertFalse((self.project / '.getzilla/getzilla/verification.py').exists())
        self.assertFalse((self.project / '.grok-stack').exists())
        self.assertEqual((self.project / '.getzilla/AGBP_SYNC.log.jsonl').read_text(encoding='utf-8'), '{"new": 1}\n')

    def test_accept_local_with_retire_legacy_removes_the_old_record(self) -> None:
        self._pre_rename()
        upgrade.sync_project(ROOT, self.project)
        git(self.project, 'switch', '--quiet', 'main')
        git(self.project, 'merge', '--quiet', '--ff-only', upgrade.BRANCH_PREFIX + upgrade.version_of(ROOT))
        git(self.project, 'branch', '-D', upgrade.BRANCH_PREFIX + upgrade.version_of(ROOT))
        (self.project / 'ruff.toml').write_text('line-length = 90\n', encoding='utf-8')
        self.commit('change a kept file')
        result = upgrade.sync_project(ROOT, self.project, accept=True, retire=True)
        self.assertIn('kept your current ruff.toml', result)
        self.assertFalse((self.project / '.grok-stack').exists())

    def test_a_missing_record_alone_does_not_make_an_update_branch(self) -> None:
        upgrade.sync_project(ROOT, self.project)
        git(self.project, 'rm', '--quiet', '.getzilla/AGBP_SYNC.json')
        self.commit('drop the record')
        head = git(self.project, 'rev-parse', 'HEAD')
        self.assertIn('up to date', upgrade.sync_project(ROOT, self.project))
        self.assertEqual(git(self.project, 'rev-parse', 'HEAD'), head)

    def test_dated_evidence_that_names_the_old_engine_does_not_block_retirement(self) -> None:
        self._pre_rename()
        evidence = self.project / 'engineering/changes/20261006-задача-1/evidence/probe.py'
        evidence.parent.mkdir(parents=True)
        evidence.write_text('from adaptive_grok import state\n', encoding='utf-8')
        self.commit('dated evidence')
        result = upgrade.sync_project(ROOT, self.project, retire=True)
        self.assertIn('dated evidence file(s)', result)
        self.assertFalse((self.project / 'scripts/grok_route.py').exists())
        self.assertTrue(evidence.is_file())

    def test_a_test_that_imports_the_old_engine_is_reported_and_blocks_retirement(self) -> None:
        self._pre_rename()
        (self.project / 'tests').mkdir()
        (self.project / 'tests/test_old.py').write_text('from adaptive_grok import verification\n', encoding='utf-8')
        self.commit('pin the old engine')
        with self.assertRaisesRegex(upgrade.UpdateError, 'tests/test_old.py'):
            upgrade.sync_project(ROOT, self.project, retire=True)
        self.assertEqual(git(self.project, 'branch', '--list'), '* main')
        self.assertIn('tests/test_old.py', upgrade.sync_project(ROOT, self.project))


class HelperTests(unittest.TestCase):
    def test_agents_merge_replaces_only_the_managed_block(self) -> None:
        installer = upgrade.load_installer(ROOT)
        block = f'{installer.MANAGED_START}\nnew\n{installer.MANAGED_END}\n'.encode()
        old = f'top\n{installer.MANAGED_START}\nold\n{installer.MANAGED_END}\nbottom\n'.encode()
        self.assertEqual(upgrade.merge_agents(installer, old, block),
                         f'top\n{installer.MANAGED_START}\nnew\n{installer.MANAGED_END}\nbottom\n'.encode())
        self.assertEqual(upgrade.merge_agents(installer, None, block), block)
        with self.assertRaisesRegex(upgrade.UpdateError, 'broken'):
            upgrade.merge_agents(installer, f'{installer.MANAGED_END}\n'.encode(), block)

    def test_getzilla_itself_is_not_a_project(self) -> None:
        self.assertIsNone(upgrade.find_project(ROOT / 'scripts', ROOT))
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp).resolve()
            (project / '.getzilla').mkdir()
            (project / 'src').mkdir()
            self.assertEqual(upgrade.find_project(project / 'src', ROOT), project)

    def test_tool_options_keep_their_old_meaning(self) -> None:
        with mock.patch.object(upgrade, 'run_tools', return_value=0) as tools, \
                mock.patch.object(upgrade, 'update_self') as update_self:
            self.assertEqual(upgrade.main(['--only', 'osv']), 0)
            self.assertEqual(upgrade.main(['--status']), 0)
            self.assertEqual(upgrade.main(['--stat']), 0)
            self.assertEqual(upgrade.main(['--no-self', '--quiet']), 0)
            self.assertEqual(upgrade.main(['tools', '--only', 'agents']), 0)
        self.assertEqual([call.args[1] for call in tools.call_args_list],
                         [['--only', 'osv'], ['--status'], ['--stat'], ['--quiet'], ['--only', 'agents']])
        update_self.assert_not_called()


class SelfUpdateTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.dict(os.environ, GIT_ENV)
        patcher.start()
        self.addCleanup(patcher.stop)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.origin, self.home, self.work = base / 'origin.git', base / 'home', base / 'work'
        subprocess.run(['git', 'init', '-q', '--bare', '--initial-branch=main', str(self.origin)], check=True)
        subprocess.run(['git', 'clone', '-q', str(self.origin), str(self.work)], check=True,
                       capture_output=True)
        self.push('one')
        subprocess.run(['git', 'clone', '-q', str(self.origin), str(self.home)], check=True)

    def push(self, text: str) -> None:
        (self.work / 'VERSION').write_text(text + '\n', encoding='utf-8')
        git(self.work, 'add', '-A')
        git(self.work, 'commit', '-q', '-m', text)
        git(self.work, 'push', '-q', 'origin', 'HEAD:main')

    def test_branch_fast_forwards_and_detached_follows_the_ref(self) -> None:
        self.push('two')
        self.assertIn('updated', upgrade.update_self(self.home, None))
        self.assertEqual((self.home / 'VERSION').read_text(encoding='utf-8'), 'two\n')
        with self.assertRaisesRegex(upgrade.UpdateError, 'detached'):
            upgrade.update_self(self.home, 'main')
        git(self.home, 'checkout', '-q', '--detach')
        self.push('three')
        self.assertIn('updated', upgrade.update_self(self.home, None))
        self.assertEqual((self.home / 'VERSION').read_text(encoding='utf-8'), 'three\n')
        self.assertEqual(git(self.home, 'rev-parse', '--is-shallow-repository'), 'false')

    def test_local_changes_skip_the_update(self) -> None:
        self.push('two')
        (self.home / 'VERSION').write_text('mine\n', encoding='utf-8')
        self.assertIn('local changes', upgrade.update_self(self.home, None))
        self.assertEqual((self.home / 'VERSION').read_text(encoding='utf-8'), 'mine\n')


if __name__ == '__main__':
    unittest.main()
