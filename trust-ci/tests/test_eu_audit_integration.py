"""Real signed EU audit integration; no container or PostgreSQL claim.

The consumer and installed verifier come from committed HEAD, never a live sibling
worktree. All temporary work stays in the canonical repository's runtime scratch.
No private signing key is written to disk.
"""
from __future__ import annotations

import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from _support import policy_data
from adaptive_trust_ci.api import create_app
from adaptive_trust_ci.holdout import bundle_digest
from adaptive_trust_ci.models import Checkout, JobRequest, utc_now
from adaptive_trust_ci.policy import Policy
from adaptive_trust_ci.runner import JobRunner
from adaptive_trust_ci.sandbox import _command_result
from adaptive_trust_ci.settings import ApiSettings, CommonSettings
from adaptive_trust_ci.signing import Signer, TrustStore
from adaptive_trust_ci.store import MemoryStore
from adaptive_trust_ci.workspace import GitWorkspace


ROOT = Path(__file__).resolve().parents[2]
AUDIT = 'scripts/getzilla_audit_bundle.py'
AUDIT_ARGV = ['python3', AUDIT, '--ci-check']
OBLIGATIONS = '.getzilla/compliance/eu-ai-act/obligations.json'
CONFIG = '.getzilla/config/compliance.json'
REGISTRY = '.getzilla/config/ai-systems.json'


def process(argv, *, cwd, env=None, timeout=60):
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True,
                          check=False, timeout=timeout)


def git(root, *args):
    result = process(['git', '-C', str(root), *args], cwd=root)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout.strip()


def isolated_environment():
    return {'PATH': os.pathsep.join((str(Path(sys.executable).parent), os.defpath)),
            'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1', 'LANG': 'C.UTF-8'}


class FixtureExecutor:
    """Test seam only: run the exact selected command, then use production results."""

    def __init__(self):
        self.calls = []

    def run(self, spec, workspace, env, max_output_bytes, *, workspace_host_path,
            holdout_path=None, holdout_host_path=None):
        if workspace != workspace_host_path:
            raise AssertionError('local fixture must use the actual workspace path')
        started = time.monotonic()
        completed = process(spec.argv, cwd=workspace,
                            env={**isolated_environment(), **env}, timeout=spec.timeout_seconds)
        result = _command_result(spec.name, completed.returncode, completed.stdout,
                                 completed.stderr, time.monotonic() - started, max_output_bytes)
        self.calls.append((spec, dict(env), result))
        return result


class LocalGitWorkspace(GitWorkspace):
    """Replace network checkout only. Retain production reset, integrity and cleanup."""

    def __init__(self, job, *, fixture, **kwargs):
        super().__init__(job, **kwargs)
        self.fixture = fixture.resolve()

    def checkout(self, job):
        if job.job_id != self.job.job_id:
            raise AssertionError('fixture job mismatch')
        self._git('init', '--quiet')
        self._git('-c', 'protocol.file.allow=always', 'fetch', '--quiet', '--no-tags',
                  str(self.fixture), job.base_sha, job.head_sha)
        self._git('checkout', '--quiet', '--detach', job.head_sha)
        if self._git_output('rev-parse', 'HEAD') != job.head_sha:
            raise AssertionError('fixture checkout differs from requested head')
        changed = self._changed_files(job.base_sha, job.head_sha)
        self.reset()
        self.assert_unchanged()
        return Checkout(self.path, changed)


class PublicationRecorder:
    def __init__(self, *, fail_once=False):
        self.fail_once = fail_once
        self.completed = []

    def ensure_check_run(self, *args, **kwargs):
        return 55

    def complete_check_run(self, *args, **kwargs):
        self.completed.append(kwargs)
        if self.fail_once and kwargs['conclusion'] == 'success':
            self.fail_once = False
            raise RuntimeError('test publication transport failed')


class EuAuditIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        common = Path(git(ROOT, 'rev-parse', '--path-format=absolute', '--git-common-dir'))
        scratch = common.parent / '.getzilla/runtime/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix='eu-audit-integration-', dir=scratch)
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        cls.source = cls.root / 'source'
        cls.source.mkdir()
        cls.source_head = git(ROOT, 'rev-parse', 'HEAD')
        paths = ['trust-ci/src', 'trust-ci/pyproject.toml', 'trust-ci/README.md', AUDIT,
                 '.getzilla/getzilla', OBLIGATIONS,
                 '.getzilla/config/diff-risk-rules.json', '.getzilla/config/cost-providers.json']
        archive = subprocess.run(['git', '-C', str(ROOT), 'archive', cls.source_head, '--', *paths],
                                 capture_output=True, check=True, timeout=30).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(cls.source, filter='data')
        cls.venv = cls.root / 'verifier-venv'
        setup = process([sys.executable, '-m', 'venv', '--system-site-packages', str(cls.venv)],
                        cwd=cls.root)
        if setup.returncode:
            raise RuntimeError('NOT_RUN: verifier venv unavailable: ' + setup.stderr)
        python = cls.venv / 'bin/python'
        install = process([str(python), '-m', 'pip', 'install', '--no-index', '--no-deps',
                           '--no-build-isolation', '--disable-pip-version-check',
                           str(cls.source / 'trust-ci')], cwd=cls.root,
                          env=isolated_environment(), timeout=60)
        if install.returncode:
            raise RuntimeError('NOT_RUN: offline verifier install failed: ' + install.stdout + install.stderr)
        cls.verifier = cls.venv / 'bin/adaptive-trust-ci'
        probe = process([str(python), '-c',
                         'import adaptive_trust_ci.models, cryptography; '
                         'print(adaptive_trust_ci.models.__file__); print(cryptography.__version__)'],
                        cwd=cls.root, env=isolated_environment())
        if probe.returncode:
            raise RuntimeError('NOT_RUN: installed verifier prerequisites unavailable: ' + probe.stderr)
        installed_module = Path(probe.stdout.splitlines()[0]).resolve()
        if cls.venv.resolve() not in installed_module.parents:
            raise AssertionError('verifier import escaped the non-editable install')
        for name in ('models.py', 'signing.py', 'cli.py'):
            if ((installed_module.parent / name).read_bytes()
                    != (cls.source / 'trust-ci/src/adaptive_trust_ci' / name).read_bytes()):
                raise AssertionError('installed verifier differs from committed source: ' + name)

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix='case-', dir=self.root))

    def consumer(self, variant='enabled'):
        root = self.case / 'consumer'
        root.mkdir()
        git(root, 'init', '-q', '-b', 'main')
        git(root, 'config', 'user.name', 'Integration fixture')
        git(root, 'config', 'user.email', 'fixture@example.invalid')
        shutil.copytree(self.source / '.getzilla/getzilla', root / '.getzilla/getzilla')
        for relative in (AUDIT, OBLIGATIONS, '.getzilla/config/diff-risk-rules.json',
                         '.getzilla/config/cost-providers.json'):
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.source / relative, target)
        matrix = json.loads((root / OBLIGATIONS).read_text())
        reviewed = datetime.now(timezone.utc).date()
        if variant == 'review':
            reviewed -= timedelta(days=181)
        matrix['reviewed'] = reviewed.isoformat()
        (root / OBLIGATIONS).write_text(json.dumps(matrix), encoding='utf-8')
        if variant != 'absent':
            (root / CONFIG).write_text(json.dumps({'enabled': [] if variant == 'disabled' else ['eu-ai-act']}),
                                       encoding='utf-8')
        systems = ([{'id': 'blocked-fixture', 'purpose': 'social scoring',
                     'class': 'prohibited', 'role': 'provider'}] if variant == 'block' else [])
        (root / REGISTRY).write_text(json.dumps({'schema_version': 'ai-systems-v1', 'systems': systems}),
                                     encoding='utf-8')
        if variant == 'missing-obligations':
            (root / OBLIGATIONS).unlink()
        (root / 'README.md').write_text('Fixture base\n', encoding='utf-8')
        git(root, 'add', '-A')
        git(root, 'commit', '-q', '-m', 'committed consumer inputs')
        base = git(root, 'rev-parse', 'HEAD')
        (root / 'README.md').write_text('Fixture head\n', encoding='utf-8')
        git(root, 'commit', '-q', '-am', 'readme-only candidate')
        return root, base, git(root, 'rev-parse', 'HEAD')

    def run_job(self, variant='enabled', *, attest=True, reject_holdout=False, replay=False):
        consumer, base, head = self.consumer(variant)
        holdout = self.case / 'holdout'
        holdout.mkdir()
        script = holdout / 'validate.py'
        script.write_text(
            'import os, subprocess, sys\n'
            'head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()\n'
            'assert head == os.environ["TRUST_CI_HEAD_SHA"]\n'
            'subprocess.run(["git", "cat-file", "-e", os.environ["TRUST_CI_BASE_SHA"] + "^{commit}"], check=True)\n'
            'print("exact fixture source checked")\n'
            'sys.exit(7 if "--reject" in sys.argv else 0)\n', encoding='utf-8')
        data = policy_data(holdout_path=str(holdout), holdout_digest=bundle_digest(holdout))
        data['allowed_repositories'] = ['owner/project']
        data['commands'] = [{'name': 'eu-ai-act-audit', 'argv': AUDIT_ARGV,
                             'timeout_seconds': 60, 'required': True, 'attest_argv': attest}]
        data['holdout']['commands'][0]['argv'] = ['python3', str(script)] + (['--reject'] if reject_holdout else [])
        policy = Policy.from_dict(data)
        store = MemoryStore()
        signer = Signer.generate()
        public_key = self.case / 'test-attestation-public.pem'
        public_key.write_bytes(signer.public_key_pem())
        request = JobRequest('owner/project', 1, base, head, 'fixture', 'main')
        store.enqueue(request, policy.digest, policy.max_attempts, now=utc_now())
        job = store.claim('fixture-worker', policy.lease_seconds, now=utc_now())
        self.assertIsNotNone(job)
        executor = FixtureExecutor()
        workspaces = []

        def workspace_factory(job, **kwargs):
            workspace = LocalGitWorkspace(job, fixture=consumer, **kwargs)
            workspaces.append(workspace)
            return workspace

        workspaces_root = self.case / 'workspaces'
        runner = JobRunner(store, policy, PublicationRecorder(fail_once=replay), signer,
                           lambda: 'test-local-checkout-only', 'https://ci.example.invalid',
                           workspaces_root, workspaces_root, holdout,
                           workspace_factory=workspace_factory, executor_factory=lambda _: executor)
        settings = ApiSettings(
            common=CommonSettings('postgresql://unused', self.case / 'policy.json',
                                  'https://ci.example.invalid', self.case / 'STOP'),
            webhook_secret='fixture-only', trust_store_path=self.case / 'unused-trust-store.json',
            read_token='fixture-read-token')
        client = TestClient(create_app(settings, store=store, policy=policy, trust_store=TrustStore({})))
        self.addCleanup(client.close)
        headers = {'Authorization': 'Bearer fixture-read-token'}
        if replay:
            with self.assertRaisesRegex(RuntimeError, 'test publication transport failed'):
                runner.process(job, 'fixture-worker')
            original = client.get(f'/attestations/{job.job_id}', headers=headers)
            self.assertEqual(original.status_code, 200)
            store.retry(job.job_id, 'fixture-worker', 'fixture publication failure', now=utc_now())
            reclaimed = store.claim('replay-worker', policy.lease_seconds, now=utc_now())
            self.assertIsNotNone(reclaimed)

            def forbid_execution(*args, **kwargs):
                raise AssertionError('replay attempted checkout or command execution')

            runner = replace(runner, github=PublicationRecorder(), workspace_factory=forbid_execution,
                             executor_factory=forbid_execution, github_token_provider=forbid_execution)
            outcome = runner.process(reclaimed, 'replay-worker')
            self.assertTrue(outcome.details['replayed'])
        else:
            outcome = runner.process(job, 'fixture-worker')
            original = client.get(f'/attestations/{job.job_id}', headers=headers)
        self.assertEqual(original.status_code, 200)
        calls = len(executor.calls)
        for _ in range(3):
            response = client.get(f'/attestations/{job.job_id}', headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, original.content)
        self.assertEqual(len(executor.calls), calls)
        self.assertEqual(store.get_attestation(job.job_id).to_dict(), original.json())
        self.assertTrue(workspaces)
        self.assertTrue(all(not item.path.exists() and not item.config_home.exists() for item in workspaces))
        self.assertEqual(git(consumer, 'status', '--porcelain', '--untracked-files=all'), '')
        self.assertFalse((consumer / '.getzilla/runtime').exists())
        self.assertEqual(original.json()['payload']['changed_files'], ['README.md'])
        self.assertEqual(original.json()['payload']['approved_scopes'], [])
        envelope = self.case / 'api-attestation.json'
        envelope.write_bytes(original.content)
        return SimpleNamespace(consumer=consumer, base=base, head=head, policy=policy, signer=signer,
                               public_key=public_key, envelope=envelope, data=original.json(),
                               executor=executor, outcome=outcome)

    def verify(self, job, envelope=None):
        return process([str(self.verifier), 'attestation-verify', '--attestation', str(envelope or job.envelope),
                        '--public-key', str(job.public_key)], cwd=self.verifier.parent,
                       env=isolated_environment())

    def bundle(self, job, envelope=None):
        out = Path(tempfile.mkdtemp(prefix='bundle-', dir=self.case))
        result = process([sys.executable, str(job.consumer / AUDIT), '--base', job.base,
                          '--repository', 'owner/project', '--attestation', str(envelope or job.envelope),
                          '--public-key', str(job.public_key), '--attestation-verifier', str(self.verifier),
                          '--out', str(out)], cwd=job.consumer, env=isolated_environment())
        self.assertIn(result.returncode, (1, 2), result.stdout + result.stderr)
        self.assertEqual(list((job.consumer / '.getzilla/runtime').rglob('*')), [])
        response = json.loads(result.stdout)
        if result.returncode == 2:
            return response
        bundle = json.loads(Path(response['bundle']).read_text())
        self.assertEqual(bundle['release_decision'], 'blocked')
        self.assertEqual(bundle['receipts'], [])
        return bundle

    def altered(self, job, name, mutate, *, resign=False):
        envelope = copy.deepcopy(job.data)
        mutate(envelope['payload'])
        if resign:
            envelope['signature'] = job.signer.sign(envelope['payload'])
        path = self.case / f'{name}.json'
        path.write_text(json.dumps(envelope), encoding='utf-8')
        return path

    def test_enabled_real_command_api_installed_verifier_and_core(self):
        job = self.run_job()
        self.assertEqual(job.outcome.status, 'passed')
        payload = job.data['payload']
        self.assertEqual(payload['schema_version'], 2)
        self.assertIsNone(payload['spec_digest'])
        self.assertIn('criterion_coverage', payload)
        spec, environment, result = job.executor.calls[-1]
        self.assertEqual(list(spec.argv), AUDIT_ARGV)
        self.assertEqual(environment['TRUST_CI_BASE_SHA'], job.base)
        audit = json.loads(result.stdout_tail)
        self.assertEqual((audit['commit'], audit['comparison_base']), (job.head, job.base))
        self.assertEqual((audit['decision'], audit['authority']), ('pass', 'evidence-only'))
        self.assertNotIn('release_decision', audit)
        self.assertNotIn('receipts', audit)
        signed = payload['command_results'][-1]
        self.assertEqual(signed['argv'], AUDIT_ARGV)
        self.assertEqual(signed['output_sha256'], result.output_sha256)
        verified = self.verify(job)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(verified.stdout), payload)
        bundle = self.bundle(job)
        self.assertEqual(bundle['authority'], 'trust-ci-attested')
        self.assertIn('verification receipt', ' '.join(bundle['reasons']))

    def test_disabled_absent_and_missing_component_cannot_pass(self):
        for variant in ('disabled', 'absent', 'missing-obligations'):
            with self.subTest(variant=variant):
                self.case = Path(tempfile.mkdtemp(prefix=f'{variant}-', dir=self.root))
                job = self.run_job(variant)
                self.assertEqual(job.outcome.status, 'failed')
                self.assertEqual(job.executor.calls[-1][2].exit_code, 2)
                self.assertEqual(job.data['payload']['command_results'][-1]['argv'], AUDIT_ARGV)
                self.assertEqual(self.verify(job).returncode, 0)
                self.assertNotEqual(self.bundle(job).get('authority'), 'trust-ci-attested')

    def test_review_and_block_are_real_failed_commands(self):
        for variant in ('review', 'block'):
            with self.subTest(variant=variant):
                self.case = Path(tempfile.mkdtemp(prefix=f'{variant}-', dir=self.root))
                job = self.run_job(variant)
                self.assertEqual(job.outcome.status, 'failed')
                result = job.executor.calls[-1][2]
                self.assertEqual(result.exit_code, 1)
                self.assertEqual(json.loads(result.stdout_tail)['decision'], variant)
                self.assertEqual(self.verify(job).returncode, 0)
                self.assertNotEqual(self.bundle(job)['authority'], 'trust-ci-attested')

    def test_holdout_failure_skips_audit_without_execution_authority(self):
        job = self.run_job(reject_holdout=True)
        self.assertEqual(job.outcome.status, 'failed')
        self.assertEqual(job.data['payload']['schema_version'], 2)
        self.assertEqual([call[0].name for call in job.executor.calls], ['external-holdout'])
        self.assertTrue(all('argv' not in result for result in job.data['payload']['command_results']))
        self.assertNotEqual(self.bundle(job)['authority'], 'trust-ci-attested')

    def test_signed_payload_tampering_fails_installed_verifier_and_core(self):
        job = self.run_job()
        changes = {
            'argv': lambda payload: payload['command_results'][-1]['argv'].append('--unexecuted'),
            'version': lambda payload: payload.update(schema_version=1),
            'base': lambda payload: payload.update(base_sha='a' * 40),
        }
        for name, mutate in changes.items():
            with self.subTest(name=name):
                path = self.altered(job, name, mutate)
                self.assertNotEqual(self.verify(job, path).returncode, 0)
                self.assertNotEqual(self.bundle(job, path)['authority'], 'trust-ci-attested')
        self.assertEqual(len(job.executor.calls), 2)

    def test_strict_v2_types_survive_real_crypto_and_cli_boundary(self):
        job = self.run_job()
        changes = {
            'boolean-version': lambda payload: payload.update(schema_version=True),
            'float-version': lambda payload: payload.update(schema_version=2.0),
            'string-version': lambda payload: payload.update(schema_version='2'),
            'unknown-version': lambda payload: payload.update(schema_version=3),
            'boolean-exit': lambda payload: payload['command_results'][-1].update(exit_code=False),
            'float-exit': lambda payload: payload['command_results'][-1].update(exit_code=0.0),
            'empty-argv': lambda payload: payload['command_results'][-1].update(argv=[]),
            'missing-digest': lambda payload: payload.pop('spec_digest'),
            'missing-coverage': lambda payload: payload.pop('criterion_coverage'),
        }
        for name, mutate in changes.items():
            with self.subTest(name=name):
                path = self.altered(job, name, mutate, resign=True)
                verified = self.verify(job, path)
                self.assertNotEqual(verified.returncode, 0)
                self.assertEqual(verified.stdout, '')
                self.assertNotEqual(self.bundle(job, path)['authority'], 'trust-ci-attested')

    def test_real_legacy_v1_is_valid_but_cannot_grant_eu_authority(self):
        job = self.run_job(attest=False)
        self.assertEqual(job.outcome.status, 'passed')
        self.assertEqual(job.data['payload']['schema_version'], 1)
        verified = self.verify(job)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(verified.stdout), job.data['payload'])
        self.assertNotEqual(self.bundle(job)['authority'], 'trust-ci-attested')

        def historical(payload):
            payload.pop('spec_digest')
            payload.pop('criterion_coverage')
            payload['command_results'][-1]['argv'] = AUDIT_ARGV

        path = self.altered(job, 'legacy-raw-argv', historical, resign=True)
        verified = self.verify(job, path)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertEqual(json.loads(verified.stdout), json.loads(path.read_text())['payload'])
        self.assertNotEqual(self.bundle(job, path)['authority'], 'trust-ci-attested')

    def test_publication_retry_replays_api_envelope_without_execution(self):
        job = self.run_job(replay=True)
        self.assertEqual(job.outcome.status, 'passed')
        self.assertEqual(len(job.executor.calls), 2)
        self.assertEqual(job.outcome.details['attestation'], job.data)
        self.assertEqual(self.verify(job).returncode, 0)
        self.assertEqual(self.bundle(job)['authority'], 'trust-ci-attested')
