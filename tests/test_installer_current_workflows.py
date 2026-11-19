"""Tiny owned workflow data; acquisition and route effects are explicitly mocked."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'.getzilla'))
from getzilla import baseline_assets


class CurrentWorkflowTests(unittest.TestCase):
    def setUp(self):
        from getzilla import current_workflows
        self.module = current_workflows
        parent = ROOT/'.getzilla/runtime/scratch'
        parent.mkdir(parents=True, exist_ok=True)
        owned = tempfile.TemporaryDirectory(prefix='owned-current-workflow-', dir=parent)
        self.addCleanup(owned.cleanup)
        self.root = Path(owned.name)
        self.project = self.root/'project'
        self.project.mkdir()
        self.home = self.root/'home'
        self.home.mkdir()

    def acquire(self, version, body):
        payload = baseline_assets.AssetPayload('superpowers', 'qwen', version*64,
                                               (('.agents/skills/inert/SKILL.md', body, 0o644),))
        return {'superpowers': (payload, {'version': version, 'commit': version*40})}

    def test_current_workflow_keeps_mandatory_security_availability(self):
        from getzilla import baseline
        import zipfile
        acquired = self.acquire('a', b'current inert skill')
        relative, body, mode = acquired['superpowers'][0].files[0]
        target = self.project / relative
        target.parent.mkdir(parents=True)
        target.write_bytes(body)
        target.chmod(mode)
        (self.home / 'workflow-current.json').write_text('{}')
        with patch.object(self.module, '_acquire', return_value=acquired):
            missing = baseline.inspect(self.home, self.project, 'qwen', which=lambda name: None, environ={})
            self.assertFalse(missing.complete)
            self.assertEqual(missing.missing, ['SECURITY_BASELINE_MISSING:osv', 'SECURITY_BASELINE_MISSING:opengrep'])
            self.assertEqual(missing.details['freshness'], 'fresh-official-source')
            # Malformed layout is no security installation. Workflow stays valid.
            (self.home / 'osv').mkdir()
            (self.home / 'osv/corrupt.json').write_text('not an OSV archive')
            (self.home / 'bin/opengrep').mkdir(parents=True)
            corrupt = baseline.inspect(self.home, self.project, 'qwen', which=lambda name: None, environ={})
            self.assertEqual(corrupt.missing, missing.missing)
            online = baseline.inspect(self.home, self.project, 'qwen',
                                      which=lambda name: '/inert/bin/opengrep',
                                      environ={'GETZILLA_OSV_ONLINE': '1'})
            self.assertTrue(online.complete, online.missing)
            self.assertEqual(online.details['security'], {'osv': True, 'opengrep': True})
            (self.home / 'bin/opengrep').rmdir()
            (self.home / 'bin/opengrep').write_bytes(b'inert availability fixture')
            (self.home / 'osv/PyPI').mkdir()
            with zipfile.ZipFile(self.home / 'osv/PyPI/all.zip', 'w') as archive:
                archive.writestr('inert.json', '{}')
            valid = baseline.inspect(self.home, self.project, 'qwen', which=lambda name: None, environ={})
            self.assertTrue(valid.complete, valid.missing)
            self.assertEqual(valid.details['security'], {'osv': True, 'opengrep': True})
            target.write_bytes(b'tampered current payload')
            tampered = baseline.inspect(self.home, self.project, 'qwen', which=lambda name: None, environ={})
            self.assertFalse(tampered.complete)
            self.assertTrue(any(item.startswith('CURRENT_WORKFLOW_UNESTABLISHED:') for item in tampered.missing))

    def test_fresh_payload_updates_owned_bytes_but_preserves_user_edit(self):
        with patch.object(self.module, '_acquire', return_value=self.acquire('a', b'first')), \
             patch.object(self.module.state, 'route_authority_present', return_value=False):
            self.module.apply_latest(self.project, 'qwen', self.home, fetch=lambda u: self.fail(u))
        path = self.project/'.agents/skills/inert/SKILL.md'
        with patch.object(self.module, '_acquire', return_value=self.acquire('b', b'second')), \
             patch.object(self.module.state, 'route_authority_present', return_value=False):
            result = self.module.apply_latest(self.project, 'qwen', self.home, fetch=lambda u: self.fail(u))
        self.assertEqual(path.read_bytes(), b'second')
        self.assertTrue(all(s.status == 'ok' for s in result))
        path.write_bytes(b'user edit')
        with patch.object(self.module, '_acquire', return_value=self.acquire('c', b'third')), \
             patch.object(self.module.state, 'route_authority_present', return_value=False):
            result = self.module.apply_latest(self.project, 'qwen', self.home, fetch=lambda u: self.fail(u))
        self.assertEqual(path.read_bytes(), b'user edit')
        self.assertEqual(result[0].status, 'fail')

    def test_no_scope_cannot_publish_constructor_payload(self):
        payload, _ = self.acquire('a', b'forged')['superpowers']
        with self.assertRaises(ValueError):
            self.module._publish(self.project, payload)
        self.assertEqual(list(self.project.iterdir()), [])

    def test_source_failure_identifies_boundary_without_raw_git_output(self):
        commit = 'a'*40
        for phase, results, reason in (
                ('init', [(128, b'', b'fatal: Permission denied secret-token /private/path')], 'permission'),
                ('fetch', [(0, b'', b''), (128, b'', b'fatal: unable to find remote helper for https secret-token')], 'helper-unavailable'),
                ('fetch', [(0, b'', b''), (1, b'', b'unknown private failure secret-token')], 'unclassified')):
            with self.subTest(phase=phase, reason=reason), \
                 patch.object(self.module, '_run_capped', side_effect=results) as run, \
                 patch.object(self.module, 'read_pinned_tree') as read:
                with self.assertRaises(ValueError) as caught:
                    self.module._source(self.home, 'obra/superpowers', commit, ('skills/',), version='7.0.2')
                text = str(caught.exception)
                self.assertIn('component=superpowers version=7.0.2 commit='+commit, text)
                self.assertIn('phase='+phase+' exit='+str(results[-1][0])+' reason='+reason, text)
                self.assertNotIn('secret-token', text)
                self.assertNotIn('/private/path', text)
                self.assertNotIn('https', text)
                self.assertEqual(run.call_count, len(results))
                read.assert_not_called()
                self.assertEqual(list((self.home/'workflow-sources').glob('current-*')), [])

    def test_source_runner_bounds_and_exec_failures_stay_closed(self):
        for error, reason in (
                (self.module.ArchitectureError('secret-token', code='timeout'), 'timeout'),
                (self.module.ArchitectureError('secret-token', code='limit'), 'output-limit'),
                (self.module.ArchitectureError('secret-token', code='git'), 'git-unavailable'),
                (self.module.ArchitectureError('secret-token', code='io'), 'runner-io'),
                (FileNotFoundError('secret-token'), 'exec-unavailable'),
                (OSError('secret-token'), 'exec-io')):
            with self.subTest(reason=reason), \
                 patch.object(self.module, '_run_capped', side_effect=[(0, b'', b''), error]) as run, \
                 patch.object(self.module, 'read_pinned_tree') as read:
                with self.assertRaises(ValueError) as caught:
                    self.module._source(self.home, 'obra/superpowers', 'b'*40, ('skills/',), version='7.0.2')
                text = str(caught.exception)
                self.assertIn('phase=fetch exit=not-returned reason='+reason, text)
                self.assertNotIn('secret-token', text)
                read.assert_not_called()
                self.assertEqual(run.call_count, 2)

    def test_source_success_keeps_exact_fetch_policy_and_payload_reader(self):
        from types import SimpleNamespace
        commit = 'c'*40
        with patch.object(self.module, '_run_capped', return_value=(0, b'', b'')) as run, \
             patch.object(self.module, 'read_pinned_tree', return_value=SimpleNamespace(files={'skills/inert.md': b'inert'})) as read:
            result = self.module._source(self.home, 'obra/superpowers', commit, ('skills/',), version='7.0.2')
        self.assertEqual(result, {'skills/inert.md': b'inert'})
        self.assertEqual(run.call_count, 2)
        command = run.call_args.args[0]
        self.assertEqual(command[-7:], ['protocol.https.allow=always', 'fetch', '-q', '--depth=1', '--no-tags', 'https://github.com/obra/superpowers.git', commit])
        self.assertIn('protocol.allow=never', command)
        env = run.call_args.kwargs['env']
        self.assertEqual(env['GIT_CONFIG_GLOBAL'], self.module.os.devnull)
        self.assertEqual(env['GIT_CONFIG_NOSYSTEM'], '1')
        self.assertEqual(env['GIT_TERMINAL_PROMPT'], '0')
        self.assertEqual(set(env)-{'PATH', 'SystemRoot', 'WINDIR'}, {'HOME', 'USERPROFILE', 'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_TERMINAL_PROMPT', 'GIT_ASKPASS', 'GIT_NO_REPLACE_OBJECTS'})
        for call in run.call_args_list:
            self.assertEqual((call.kwargs['stdout_limit'], call.kwargs['stderr_limit'], call.kwargs['timeout']), (4096, 4096, 60))
        self.assertEqual(read.call_args.args[1], commit)
        self.assertEqual(read.call_args.kwargs['prefixes'], ('skills/',))

    def test_acquire_binds_resolved_version_to_source_diagnostic(self):
        spec = {'repository': 'obra/superpowers', 'pinned_commit': 'd'*40}
        release = {'version': '7.0.2', 'tag_name': 'v7.0.2', 'metadata_sha256': 'e'*64}
        with patch.object(self.module, 'components', return_value={'superpowers': spec}), \
             patch.object(self.module, 'github_release', return_value=release), \
             patch.object(self.module, '_commit', return_value='f'*40), \
             patch.object(self.module, '_source', return_value={'skills/inert/SKILL.md': b'inert'}) as source:
            self.module._acquire(self.home, 'claude', lambda url: self.fail(url))
        self.assertEqual(source.call_args.kwargs, {'version': '7.0.2'})

    def test_source_diagnostic_does_not_echo_unvalidated_identity(self):
        with patch.object(self.module, '_run_capped', return_value=(128, b'', b'secret-token')):
            with self.assertRaises(ValueError) as caught:
                self.module._source(self.home, 'secret-token', 'secret-token', ('skills/',), version='1'*1000+'.2')
        text = str(caught.exception)
        self.assertIn('component=unknown version=unknown commit=unknown', text)
        self.assertNotIn('secret-token', text)
        self.assertLess(len(text), 250)

    def test_unknown_new_source_format_refuses(self):
        with self.assertRaises(ValueError):
            self.module.spec_payload({'unknown.txt': b'inert'}, 'qwen', '9.0.0', 'a'*40, windows=False)

    def test_new_file_policy_refusal_prevents_all_publication(self):
        with patch.object(self.module, '_acquire', return_value=self.acquire('a', b'first')), \
             patch.object(self.module.state, 'route_authority_present', return_value=True), \
             patch.object(self.module.state, 'require_route_owner'), \
             patch.object(self.module, 'evaluate_pre_tool', return_value=(False, 'inert policy denial')):
            result = self.module.apply_latest(self.project, 'qwen', self.home, fetch=lambda u: self.fail(u))
        self.assertEqual(result[0].status, 'fail')
        self.assertFalse((self.project/'.agents/skills/inert/SKILL.md').exists())

    def test_spec_data_adapter_binds_current_template_scripts_and_platform(self):
        source = {'templates/constitution-template.md': b'new constitution',
                  'templates/plan-template.md': b'new major plan',
                  'workflows/speckit/workflow.yml': b'version: 2.0.0\n',
                  'scripts/bash/owned.sh': b'inert shell source',
                  'scripts/powershell/owned.ps1': b'inert PowerShell source'}
        for stem in ('plan', 'specify', 'tasks', 'implement', 'constitution'):
            source['templates/commands/'+stem+'.md'] = b'---\ndescription: Owned command\nscripts:\n  sh: scripts/bash/owned.sh --json\n  ps: scripts/powershell/owned.ps1 -Json\n---\nRun {SCRIPT}\n'
        payload = self.module.spec_payload(source, 'codex', '2.0.0', 'b'*40, windows=True)
        files = {n: b for n, b, _ in payload.files}
        command = files['.agents/skills/speckit-plan/SKILL.md']
        self.assertIn(b'.specify/scripts/powershell/owned.ps1 -Json', command)
        self.assertNotIn(b'{SCRIPT}', command)
        self.assertEqual(files['.specify/templates/plan-template.md'], b'new major plan')
        self.assertIn(b'2.0.0', files['.specify/init-options.json'])
        self.assertFalse(payload.permissions_granted)
        del source['scripts/powershell/owned.ps1']
        with self.assertRaises(ValueError):
            self.module.spec_payload(source, 'codex', '2.0.0', 'b'*40, windows=True)

    def test_policy_revoked_after_preflight_refuses_publication(self):
        acquired=self.acquire('a', b'first')
        payload=acquired['superpowers'][0]
        with patch.object(self.module, '_acquire', return_value=acquired), \
             patch.object(self.module.baseline_assets,'load',return_value=payload), \
             patch.object(self.module.state,'route_authority_present',return_value=True), \
             patch.object(self.module.state,'require_route_owner'), \
             patch.object(self.module,'evaluate_pre_tool',side_effect=[(True,'owned initial'),(False,'revoked')]):
            result=self.module.apply_latest(self.project,'qwen',self.home,fetch=lambda u:self.fail(u))
        self.assertEqual(result[0].status,'fail')
        self.assertFalse((self.project/'.agents/skills/inert/SKILL.md').exists())
