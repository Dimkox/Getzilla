"""Owned Git capability/control fixtures; no compiler, network or vendor source runs."""
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
from getzilla import architecture_diff, managed_software, managed_source_build
from getzilla.latest_releases import Target
from getzilla.managed_npm import publish_command

CAPABILITIES = b'stateless-connect\nfetch\nget\noption\npush\ncheck-connectivity\nobject-format\n\n'
MISSING_HELPER = b"git: 'remote-https' is not a git command. See 'git --help'."


class GitHTTPSControls(unittest.TestCase):
    def setUp(self):
        effects = ExitStack()
        self.addCleanup(effects.close)
        effects.enter_context(patch.dict(os.environ))
        for name in ('socket.socket', 'socket.getaddrinfo', 'subprocess.Popen'):
            effects.enter_context(patch(name, side_effect=AssertionError('outside effect denied')))
        scratch = ROOT / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        owned = tempfile.TemporaryDirectory(prefix='owned-git-https-', dir=scratch)
        self.addCleanup(owned.cleanup)
        self.root = Path(owned.name)
        self.target = Target('git', '2.56.1', 'https://owned.invalid/git.tar.gz', sha256='a' * 64)

    def version(self, command, cwd=None, **kwargs):
        return subprocess.CompletedProcess(command, 0, 'git version 2.56.1', '')

    def test_exact_version_without_https_is_refused_before_source_admission(self):
        for reply in ((128, b'', b'helper unavailable secret-token'),
                      (0, b'fetch\n', b''), (0, b'option\n\n', b''), (0, b'fetch\noption\nfetch\n\n', b''),
                      (0, b'fetch\noption\nunknown secret-token\n\n', b'')):
            with self.subTest(reply=reply), patch.object(architecture_diff, '_run_capped', return_value=reply):
                with self.assertRaisesRegex(ValueError, 'HTTPS') as caught:
                    managed_source_build._probe(self.target, self.root / 'git', self.root, {}, self.version)
                self.assertNotIn('secret-token', str(caught.exception))

    def test_probe_runner_faults_refuse_without_raw_exception_details(self):
        for error in (architecture_diff.ArchitectureError('secret-token', code='timeout'),
                      architecture_diff.ArchitectureError('secret-token', code='limit'), OSError('secret-token')):
            with self.subTest(error=type(error).__name__), patch.object(architecture_diff, '_run_capped', side_effect=error):
                with self.assertRaisesRegex(ValueError, 'HTTPS') as caught:
                    managed_source_build._probe(self.target, self.root / 'git', self.root, {}, self.version)
                self.assertNotIn('secret-token', str(caught.exception))
                self.assertFalse(list(self.root.glob('git-https-probe-*')))

    def test_healthy_helper_uses_only_bounded_private_capability_protocol(self):
        calls = []
        def capped(command, **kwargs):
            calls.append((command, kwargs))
            self.assertTrue(kwargs['cwd'].is_relative_to(self.root))
            self.assertTrue(kwargs['cwd'].is_dir())
            return 0, CAPABILITIES, b''
        with patch.object(architecture_diff, '_run_capped', side_effect=capped):
            managed_source_build._probe(self.target, self.root / 'git', self.root,
                                       dict(PATH='owned-path', GIT_EXEC_PATH='untrusted', PRIVATE='secret-token'), self.version)
        self.assertEqual(len(calls), 1)
        command, values = calls[0]
        self.assertIn('remote-https', command)
        self.assertEqual(command[-2:], ['getzilla-probe', 'https://github.com/'])
        self.assertEqual(values['stdin_data'], b'capabilities\n\n')
        self.assertEqual((values['timeout'], values['stdout_limit'], values['stderr_limit']), (10, 4096, 4096))
        self.assertNotIn('GIT_EXEC_PATH', values['env'])
        self.assertNotIn('PRIVATE', values['env'])
        self.assertEqual(values['env']['PATH'], str(values['cwd']))
        self.assertEqual(values['env']['GIT_CONFIG_GLOBAL'], os.devnull)
        self.assertFalse(values['cwd'].exists(), 'private probe directory must be removed')

    def fixture(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            member = tarfile.TarInfo('git-2.56.1/configure')
            member.size, member.mode = 5, 0o755
            archive.addfile(member, io.BytesIO(b'owned'))
        raw = stream.getvalue()
        return Target('git', '2.56.1', 'https://owned.invalid/git-2.56.1.tar.gz',
                      sha256=hashlib.sha256(raw).hexdigest(), filename='git-2.56.1.tar.gz'), raw

    def builder(self, calls, *, no_curl=False):
        prefix = None
        def run(command, cwd=None, **kwargs):
            nonlocal prefix
            calls.append(command)
            if command[0] == './configure':
                prefix = Path(command[1].removeprefix('--prefix='))
                (cwd / 'config.mak.autogen').write_text('NO_CURL=' + ('YesPlease' if no_curl else '') + '\n')
            elif command[:2] == ['make', 'install']:
                (prefix / 'bin').mkdir(parents=True)
                (prefix / 'bin/git').write_bytes(b'inert exact Git')
            return self.version(command, cwd, **kwargs)
        return run

    def test_curl_disabled_config_refuses_before_compilation_or_custody(self):
        target, raw = self.fixture()
        calls = []
        with patch.object(architecture_diff, '_run_capped', return_value=(0, CAPABILITIES, b'')):
            with self.assertRaisesRegex(ValueError, 'libcurl'):
                managed_source_build.install_source(target, raw, self.root, run=self.builder(calls, no_curl=True))
        self.assertEqual(len(calls), 1)
        self.assertFalse((self.root / 'source-builds' / ('git-' + target.sha256 + '.json')).exists())

    def test_reused_custody_is_not_returned_when_helper_becomes_unavailable(self):
        target, raw = self.fixture()
        calls = []
        run = self.builder(calls)
        with patch.object(architecture_diff, '_run_capped', return_value=(0, CAPABILITIES, b'')):
            managed_source_build.install_source(target, raw, self.root, run=run)
        hint = self.root / 'source-builds' / ('git-' + target.sha256 + '.json')
        original = hint.read_bytes()
        old = Path(json.loads(original)['stage'])
        old = self.root / 'source-builds' / old / 'installed/bin/git'
        wrapper = publish_command(self.root, 'git', [str(old)])
        active = wrapper.read_bytes()
        ledger = (self.root / 'managed-command-hashes.json').read_bytes()
        with patch.object(managed_software, 'plan', return_value=({'git': target}, [])), \
             patch.object(managed_software, 'verify_environment', return_value=dict(component='python-environment', status='complete')), \
             patch.object(managed_software, 'publish_command', wraps=publish_command) as publish, \
             patch.object(architecture_diff, '_run_capped', return_value=(128, b'', MISSING_HELPER)):
            report = managed_software.install_software(self.root, ROOT, fetch=lambda _: raw, run=run, system='linux', architecture='x64')
            self.assertEqual(report['status'], 'incomplete', report)
            self.assertIn('HTTPS', report['components'][0]['error'])
            publish.assert_not_called()
        self.assertEqual(hint.read_bytes(), original)
        self.assertEqual(wrapper.read_bytes(), active)
        self.assertEqual((self.root / 'managed-command-hashes.json').read_bytes(), ledger)
        self.assertEqual(len([command for command in calls if command[0] == 'make']), 4,
                         'one fresh build attempt, then refusal without recursive retry')
        self.assertEqual(len(list((self.root / 'source-builds').glob('git-2.56.1-*'))), 2)

    def test_version_and_custody_conflicts_cannot_trigger_recovery(self):
        target, raw = self.fixture()
        for tamper in (False, True):
            with self.subTest(tamper=tamper):
                root = self.root / str(tamper)
                root.mkdir()
                calls = []
                run = self.builder(calls)
                with patch.object(architecture_diff, '_run_capped', return_value=(0, CAPABILITIES, b'')):
                    old = managed_source_build.install_source(target, raw, root, run=run)
                if tamper:
                    old.write_bytes(b'user change')
                def wrong_version(command, cwd=None, **kwargs):
                    return subprocess.CompletedProcess(command, 0, 'git version 2.55.0', '')
                with patch.object(architecture_diff, '_run_capped', side_effect=AssertionError('no helper/recovery after conflict')):
                    with self.assertRaisesRegex(ValueError, 'custody conflict' if tamper else 'built actual'):
                        managed_source_build.install_source(target, raw, root, run=wrong_version)
                self.assertEqual(len(list((root / 'source-builds').glob('git-2.56.1-*'))), 1)

    def test_unknown_or_incomplete_helper_failures_do_not_trigger_rebuild(self):
        target, raw = self.fixture()
        for number, failure in enumerate(((128, b'', b'unknown private failure'), (0, b'malformed\n', b''),
                                           architecture_diff.ArchitectureError('private timeout', code='timeout'))):
            with self.subTest(number=number):
                root = self.root / ('unknown-' + str(number))
                root.mkdir()
                calls = []
                run = self.builder(calls)
                with patch.object(architecture_diff, '_run_capped', return_value=(0, CAPABILITIES, b'')):
                    managed_source_build.install_source(target, raw, root, run=run)
                keywords = dict(side_effect=failure) if isinstance(failure, Exception) else dict(return_value=failure)
                with patch.object(architecture_diff, '_run_capped', **keywords), self.assertRaises(ValueError):
                    managed_source_build.install_source(target, raw, root, run=run)
                self.assertEqual(len(list((root / 'source-builds').glob('git-2.56.1-*'))), 1)

    def test_valid_broken_cache_gets_one_fresh_build_then_one_normal_publication(self):
        target, raw = self.fixture()
        calls = []
        run = self.builder(calls)
        with patch.object(architecture_diff, '_run_capped', return_value=(0, CAPABILITIES, b'')):
            old = managed_source_build.install_source(target, raw, self.root, run=run)
        wrapper = publish_command(self.root, 'git', [str(old)])
        old_bytes = old.read_bytes()
        old_custody = (old.parents[2] / 'build-custody.json').read_bytes()
        def capabilities(command, **kwargs):
            return (128, b'', MISSING_HELPER) if command[0] == str(old) else (0, CAPABILITIES, b'')
        with patch.object(managed_software, 'plan', return_value=({'git': target}, [])), \
             patch.object(managed_software, 'verify_environment', return_value=dict(component='python-environment', status='complete')), \
             patch.object(managed_software, 'publish_command', wraps=publish_command) as publish, \
             patch.object(architecture_diff, '_run_capped', side_effect=capabilities):
            report = managed_software.install_software(self.root, ROOT, fetch=lambda _: raw, run=run, system='linux', architecture='x64')
            self.assertEqual(report['status'], 'complete', report)
            new = Path(report['components'][0]['path'])
            self.assertNotEqual(new, old)
            self.assertEqual(publish.call_count, 1)
            self.assertIn(str(new).encode(), wrapper.read_bytes())
            stable = wrapper.read_bytes()
            again = managed_software.install_software(self.root, ROOT, fetch=lambda _: raw, run=run, system='linux', architecture='x64')
            self.assertEqual(again['status'], 'complete', again)
            self.assertEqual(again['components'][0]['path'], str(new))
            self.assertEqual(wrapper.read_bytes(), stable)
            self.assertEqual(publish.call_count, 2, 'one publication per requested installer invocation')
        self.assertEqual(old.read_bytes(), old_bytes)
        self.assertEqual((old.parents[2] / 'build-custody.json').read_bytes(), old_custody)
        self.assertEqual(len([command for command in calls if command[0] == 'make']), 4)

    def test_managed_publication_and_verify_refuse_version_only_git(self):
        for verify_only in (False, True):
            with self.subTest(verify_only=verify_only):
                state = self.root / ('verify' if verify_only else 'publish')
                path = state / 'bin/git'
                with patch.object(managed_software, 'plan', return_value=({'git': self.target}, [])), \
                     patch.object(managed_software, 'verify_environment', return_value=dict(component='python-environment', status='complete')), \
                     patch.object(managed_software, 'install_runtime', return_value=path), \
                     patch.object(managed_software, 'publish_command') as publish, \
                     patch.object(architecture_diff, '_run_capped', return_value=(128, b'', b'helper unavailable')):
                    report = managed_software.install_software(state, self.root, fetch=lambda _: b'owned', run=self.version,
                        which=lambda _: str(path), system='windows' if not verify_only else 'linux', architecture='x64', verify_only=verify_only)
                self.assertEqual(report['status'], 'incomplete')
                self.assertIn('HTTPS', report['components'][0]['error'])
                publish.assert_not_called()

