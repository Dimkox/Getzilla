"""Owned public adapter fixtures: planning is inert; publication uses Git rollback."""
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / '.getzilla'), str(ROOT / 'scripts')]

from getzilla import harnesses  # noqa: E402
from getzilla import adapter_removal as publication  # noqa: E402
from getzilla.component_state import MANIFEST, V2, BoundRoot, encode_manifest, record_owned  # noqa: E402


class RemovalPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.project = Path(temporary.name) / 'project'
        self.project.mkdir()
        self.selected = (*harnesses.HARNESSES, 'cursor')
        with BoundRoot(ROOT) as source:
            self.outputs = harnesses._render(source, self.selected)
        self.manifest = {'schema_version': V2, 'agents': list(self.selected), 'components': {}}
        for path, content in self.outputs.items():
            self.put(path, content)
        self.put('.codex/user.txt', b'foreign user bytes', owned=False)
        self.save()

    def put(self, path: str, content: bytes, *, owned: bool = True, mode: int = 0o644) -> None:
        target = self.project / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(mode)
        if owned:
            record_owned(self.manifest, path, content, mode)

    def save(self) -> None:
        self.put(MANIFEST, encode_manifest(self.manifest), owned=False)

    def plan(self, agents=None):
        from getzilla.adapter_removal import plan_removal
        with BoundRoot(self.project) as binding:
            return plan_removal(ROOT, binding, agents)

    def test_all_formats_preserve_entire_and_unknown_without_publication(self) -> None:
        before = copy.deepcopy(self.manifest)
        plan = self.plan()
        self.assertEqual(plan.manifest['agents'], [])
        changes = {p: c for p, c, _ in plan.changes}
        for agent in ('qwen', 'claude', 'gemini', 'grok'):
            path = f'.{agent}/' + ('hooks.json' if agent == 'grok' else 'settings.json')
            self.assertIsNone(changes[path], path)
        self.assertIsNone(changes['.github/hooks/getzilla.json'])
        self.assertIsNotNone(changes['.codex/hooks.json'])
        codex = json.loads(changes['.codex/hooks.json'])
        commands = str(codex)
        self.assertIn('entire hooks codex', commands)
        self.assertNotIn('.getzilla/hooks/', commands)
        self.assertNotIn('.codex/config.toml', changes)
        self.assertNotIn('.codex/user.txt', changes)
        self.assertEqual(self.manifest, before)
        self.assertEqual((self.project / MANIFEST).read_bytes(), encode_manifest(before))
        self.assertEqual(plan.native_state, 'unverified')
        self.assertTrue(all((self.project / p).exists() for p, c in self.outputs.items()))

    def test_custom_native_fields_and_hook_groups_survive_exact_subtraction(self) -> None:
        path = '.claude/settings.json'
        data = json.loads(self.outputs[path])
        foreign = {'hooks': [{'type': 'command', 'command': 'echo public-fixture-only'}]}
        data['hooks']['Stop'].append(foreign)
        data['user'] = {'retain': True}
        self.put(path, json.dumps(data).encode())
        self.save()
        plan = self.plan(('claude',))
        contents = dict((p, c) for p, c, _ in plan.changes)[path]
        self.assertIsNotNone(contents)
        result = json.loads(contents)
        self.assertEqual(result, {'hooks': {'Stop': [foreign]}, 'user': {'retain': True}})
        self.assertNotIn(path, plan.manifest['components']['agent:claude'].get('owned', {}))
        self.assertEqual(plan.manifest['agents'], [x for x in self.selected if x != 'claude'])

    def test_changed_bytes_mode_missing_proof_and_kept_paths_refuse(self) -> None:
        path = '.codex/agents/general_implementer.toml'
        original = (self.project / path).read_bytes()
        for scenario in ('bytes', 'mode', 'proof', 'owned-custom-policy', 'kept'):
            with self.subTest(scenario=scenario):
                (self.project / path).chmod(0o644)  # reset only the preceding owned fixture case
                self.put(path, original)
                if scenario == 'bytes':
                    self.put(path, original + b'\n# changed', owned=False)
                elif scenario == 'mode':
                    (self.project / path).chmod(0o444)
                elif scenario == 'proof':
                    self.manifest['components']['agent:codex']['owned'].pop(path)
                elif scenario == 'owned-custom-policy':
                    self.put(path, original.replace(b'workspace-write', b'read-only'))
                elif scenario == 'kept':
                    self.put('.getzilla/AGBP_SYNC.json', json.dumps({'schema_version': 1, 'kept_local': [path]}).encode(), owned=False)
                self.save()
                manifest_before = (self.project / MANIFEST).read_bytes()
                content_before = (self.project / path).read_bytes()
                mode_before = (self.project / path).stat().st_mode
                with self.assertRaises(ValueError):
                    self.plan(('codex',))
                self.assertEqual((self.project / MANIFEST).read_bytes(), manifest_before)
                self.assertEqual((self.project / path).read_bytes(), content_before)
                self.assertEqual((self.project / path).stat().st_mode, mode_before)

    def test_modified_duplicate_and_invalid_native_groups_refuse(self) -> None:
        path = '.qwen/settings.json'
        data = json.loads(self.outputs[path])
        modified = copy.deepcopy(data)
        modified['hooks']['Stop'][0]['hooks'][0]['command'] += ' changed'
        duplicated = copy.deepcopy(data)
        duplicated['hooks']['Stop'] *= 2
        for content in (json.dumps(modified).encode(), json.dumps(duplicated).encode(), b'{"hooks":{},"hooks":{}}', b'[]'):
            with self.subTest(content=content[:25]):
                self.put(path, content)
                self.save()
                with self.assertRaises(ValueError):
                    self.plan(('qwen',))

    def test_unselected_and_unknown_component_files_are_retained(self) -> None:
        self.put('.codex/private-unknown.toml', b'not a Getzilla generated role')
        self.save()
        plan = self.plan(('claude',))
        paths = {p for p, _, _ in plan.changes}
        self.assertFalse(any(p.startswith('.codex/') for p in paths))
        self.assertNotIn('.codex/private-unknown.toml', paths)

    def test_unowned_custom_codex_activation_stays_when_entire_remains(self) -> None:
        path = '.codex/config.toml'
        self.put(path, b'[features]\ncodex_hooks = true\n[user]\nretain = true\n', owned=False)
        self.manifest['components']['agent:codex']['owned'].pop(path)
        self.save()
        plan = self.plan(('codex',))
        self.assertNotIn(path, {p for p, _, _ in plan.changes})
        self.assertIn(path, plan.retained)

    def test_remaining_grok_hooks_keep_unowned_custom_activation(self) -> None:
        path = '.grok/hooks.json'
        data = json.loads(self.outputs[path])
        foreign = {'hooks': [{'command': 'echo public foreign'}]}
        data['hooks']['Stop'].append(foreign)
        self.put(path, json.dumps(data).encode())
        config = b'[features]\nhooks = true\n[user]\nretain = true\n'
        self.put('.grok/config.toml', config, owned=False)
        self.save()
        plan = self.plan(('grok',))
        self.assertNotIn('.grok/config.toml', {p for p, _, _ in plan.changes})
        self.assertIn('.grok/config.toml', plan.retained)
        self.assertEqual((self.project / '.grok/config.toml').read_bytes(), config)
        self.assertEqual(json.loads(dict((p, c) for p, c, _ in plan.changes)[path]), {'hooks': {'Stop': [foreign]}})

    def test_remaining_qwen_hooks_keep_their_context(self) -> None:
        path = '.qwen/settings.json'
        data = json.loads(self.outputs[path])
        foreign = {'hooks': [{'command': 'echo public foreign'}]}
        data['hooks']['Stop'].append(foreign)
        self.put(path, json.dumps(data).encode())
        self.save()
        plan = self.plan(('qwen',))
        result = json.loads(dict((p, c) for p, c, _ in plan.changes)[path])
        self.assertEqual(result, {'context': data['context'], 'hooks': {'Stop': [foreign]}})

    def test_manifest_keep_and_native_resource_limits_refuse_without_effect(self) -> None:
        from getzilla.adapter_removal import MAX_NATIVE_BYTES
        path = '.qwen/settings.json'
        for content in (b'{"hooks":{},"padding":"' + b'x' * MAX_NATIVE_BYTES + b'"}',
                        b'{"hooks":{"Stop":' + b'[' * 1100 + b']' * 1100 + b'}}',
                        b'{"hooks":{"Stop":[NaN]}}', b'{"hooks":{},"extra":1e309}', b'\xef\xbb\xbf{"hooks":{}}',
                        b'{"hooks":{},"extra":' + b'[' * 66 + b'0' + b']' * 66 + b'}',
                        b'{"hooks":{},"extra":"\\ud800"}'):
            with self.subTest(content=content[:25]):
                self.put(path, content)
                self.save()
                with self.assertRaises(ValueError):
                    self.plan(('qwen',))
        self.put(path, self.outputs[path])
        self.put('.getzilla/AGBP_SYNC.json', json.dumps({'schema_version': 1, 'kept_local': [MANIFEST]}).encode(), owned=False)
        self.save()
        with self.assertRaisesRegex(ValueError, 'kept component manifest'):
            self.plan(('qwen',))

    def test_native_output_remains_within_the_same_byte_bound(self) -> None:
        extra = ['x' * 100] * 1600
        for _ in range(58):
            extra = [extra]
        data = json.loads(self.outputs['.qwen/settings.json'])
        data['extra'] = extra
        compact = json.dumps(data, separators=(',', ':')).encode()
        self.assertLess(len(compact), 262144)
        self.put('.qwen/settings.json', compact)
        self.save()
        with self.assertRaisesRegex(ValueError, 'native configuration.*bound'):
            self.plan(('qwen',))


class RemovalGitTests(unittest.TestCase):
    put = RemovalPlanTests.put
    save = RemovalPlanTests.save

    def setUp(self) -> None:
        RemovalPlanTests.setUp(self)
        patch = mock.patch.dict(os.environ, {'GIT_AUTHOR_NAME': 'public fixture',
                                            'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                                            'GIT_COMMITTER_NAME': 'public fixture',
                                            'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'})
        patch.start()
        self.addCleanup(patch.stop)
        self.put('.getzilla/getzilla/__init__.py', b'# installed fixture marker\n', owned=False)
        self.git('init', '--quiet', '--initial-branch=main')
        self.git('add', '-A')
        self.git('commit', '--quiet', '-m', 'public installed adapter fixture')
        self.original = self.git('rev-parse', 'HEAD')

    def git(self, *args: str) -> str:
        return subprocess.run(['git', '-C', str(self.project), *args], check=True,
                              text=True, capture_output=True).stdout.strip()

    def remove(self, agents=None):
        import getzilla_upgrade
        return getzilla_upgrade.remove_adapters(ROOT, self.project, agents)

    def test_git_removal_idempotence_selection_and_rollback(self) -> None:
        from getzilla.component_state import read_state
        result = self.remove()
        removed_head = self.git('rev-parse', 'HEAD')
        self.assertEqual(self.git('rev-parse', 'HEAD^'), self.original)
        self.assertEqual(result['live_client_state'], 'unverified')
        self.assertEqual(read_state(self.project).require_selection(), ())
        self.assertFalse((self.project / '.codex/agents/general_implementer.toml').exists())
        self.assertEqual((self.project / '.codex/user.txt').read_bytes(), b'foreign user bytes')
        self.assertIn('entire hooks codex', (self.project / '.codex/hooks.json').read_text())
        second = self.remove()
        self.assertEqual(second['configuration'], 'unchanged')
        self.assertEqual(self.git('rev-parse', 'HEAD'), removed_head)
        self.git('switch', '--quiet', 'main')
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        self.assertEqual((self.project / '.codex/agents/general_implementer.toml').read_bytes(),
                         self.outputs['.codex/agents/general_implementer.toml'])
        self.assertEqual(read_state(self.project).require_selection(), self.selected)

    def test_before_publication_cut_keeps_original_state_and_route(self) -> None:
        import getzilla_upgrade
        with mock.patch.object(publication, 'commit_changes', side_effect=OSError('public cut')):
            with self.assertRaises(getzilla_upgrade.UpdateError):
                self.remove(('claude',))
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        self.assertEqual(self.git('branch', '--list'), '* main')
        self.assertEqual((self.project / '.claude/settings.json').read_bytes(), self.outputs['.claude/settings.json'])

    def test_failed_checkout_retains_recoverable_commit_and_does_not_retry(self) -> None:
        import getzilla_upgrade
        original_git = publication.git
        switches = []

        def git(project, *args, **kwargs):
            if args[:2] == ('switch', '--quiet'):
                switches.append(args)
                return subprocess.CompletedProcess(args, 1, '', 'public checkout cut')
            return original_git(project, *args, **kwargs)

        with mock.patch.object(publication, 'git', side_effect=git):
            with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'checking it out failed'):
                self.remove(('claude',))
        self.assertEqual(len(switches), 1)
        branch = switches[0][2]
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        self.assertEqual(self.git('rev-parse', branch + '^'), self.original)
        self.assertEqual((self.project / '.claude/settings.json').read_bytes(), self.outputs['.claude/settings.json'])
        self.git('switch', '--quiet', branch)
        self.assertFalse((self.project / '.claude/settings.json').exists())

    def test_current_file_cut_before_ref_leaves_product_and_branch_unpublished(self) -> None:
        import getzilla_upgrade
        original = publication.commit_changes
        changed = self.project / '.claude/settings.json'

        def commit(*args, **kwargs):
            result = original(*args, **kwargs)
            changed.write_bytes(b'{"user":"concurrent public fixture"}\n')
            return result

        with mock.patch.object(publication, 'commit_changes', side_effect=commit):
            with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'uncommitted|file changed'):
                self.remove(('claude',))
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        self.assertEqual(self.git('branch', '--list'), '* main')
        self.assertIn(b'concurrent public fixture', changed.read_bytes())

    def test_after_ref_cut_reports_retained_commit_without_checkout(self) -> None:
        import getzilla_upgrade
        original = publication._git_out
        changed = self.project / '.claude/settings.json'

        def git_out(project, *args, **kwargs):
            result = original(project, *args, **kwargs)
            if args[:2] == ('update-ref', '--stdin'):
                changed.write_bytes(b'{"user":"after ref public fixture"}\n')
            return result

        with mock.patch.object(publication, '_git_out', side_effect=git_out):
            with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'retained.*checkout not completed'):
                self.remove(('claude',))
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        branches = self.git('for-each-ref', '--format=%(refname:short)', 'refs/heads/getzilla-remove-*').splitlines()
        self.assertEqual(len(branches), 1)
        self.assertEqual(self.git('rev-parse', branches[0] + '^'), self.original)
        self.assertIn(b'after ref public fixture', changed.read_bytes())

    def test_nongit_dirty_source_and_invalid_selection_refuse(self) -> None:
        import getzilla_upgrade
        with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'source checkout'):
            getzilla_upgrade.remove_adapters(ROOT, ROOT)
        with self.assertRaises(getzilla_upgrade.UpdateError):
            self.remove(('unknown',))
        self.put('user.txt', b'uncommitted foreign', owned=False)
        with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'uncommitted'):
            self.remove()
        self.assertEqual(self.git('rev-parse', 'HEAD'), self.original)
        with tempfile.TemporaryDirectory() as tmp:
            nongit = Path(tmp)
            (nongit / '.getzilla/getzilla').mkdir(parents=True)
            (nongit / '.getzilla/getzilla/__init__.py').write_bytes(b'')
            with self.assertRaisesRegex(getzilla_upgrade.UpdateError, 'root of a Git repository'):
                getzilla_upgrade.remove_adapters(ROOT, nongit)


if __name__ == '__main__':
    unittest.main()
