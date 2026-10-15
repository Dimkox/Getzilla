"""`getzilla trust-ci`: one-command Trust CI host bootstrap with an injected Docker runner (no network)."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
sys.path.insert(0, str(ROOT / 'scripts'))

from getzilla import trust_ci_setup as tcs  # noqa: E402

REAL = ROOT / 'trust-ci'
POSIX = os.name != 'nt'
ED25519_PREFIX = bytes.fromhex('302a300506032b6570032100')
WORKER_ONLY = ('TRUST_CI_GITHUB_APP_ID', 'TRUST_CI_GITHUB_INSTALLATION_ID',
               'TRUST_CI_GITHUB_APP_PRIVATE_KEY_PATH', 'TRUST_CI_SIGNING_KEY_PATH')
RSA_KEY = b'-----BEGIN RSA PRIVATE KEY-----\nMIIEdGVzdA==\n-----END RSA PRIVATE KEY-----\n'


def fake_digest(seed: str) -> str:
    return 'sha256:' + hashlib.sha256(seed.encode('utf-8')).hexdigest()


def repository(reference: str) -> str:
    head, _, last = reference.rpartition('/')
    name = last.split(':', 1)[0]
    return f'{head}/{name}' if head else name


def public_pem(raw: bytes) -> str:
    body = base64.b64encode(ED25519_PREFIX + raw).decode('ascii')
    return f'-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n'


def make_tree(base: Path) -> Path:
    trust = base / 'trust-ci'
    names = ['compose.yaml', 'compose.build.yaml', 'compose.test.yaml', '.env.example',
             'config/policy.example.json', 'config/trust-store.example.json', 'scripts/postgres-integration.sh']
    names += [f'env/{path.name}' for path in (REAL / 'env').glob('*.example')]
    for rel in names:
        (trust / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REAL / rel, trust / rel)
    (trust / 'runtime').mkdir()
    return trust


def env_values(path: Path) -> dict[str, str]:
    return tcs.read_env(path)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class Tokens:
    def __init__(self, *, forbid: bool = False) -> None:
        self.issued: list[str] = []
        self.forbid = forbid

    def __call__(self) -> str:
        if self.forbid:
            raise AssertionError('a secret was generated on a run that had nothing missing')
        value = f'tok{len(self.issued):03d}-' + 'Zq_9' * 8
        self.issued.append(value)
        return value


@dataclass
class Call:
    args: list[str]
    cwd: Path
    env: dict[str, str]


class FakeHost:
    """Docker, the keygen tool and the live harness as seen by `trust_ci_setup` through its runner."""

    def __init__(self, *, local=('postgres:17.6-bookworm',), volumes=(), projects=(), crypto=True,
                 fail: str | None = None, failure_output: str = '') -> None:
        self.calls: list[Call] = []
        self.images = {ref: [f'{repository(ref)}@{fake_digest(ref)}'] for ref in local}
        self.volumes = set(volumes)
        self.projects = list(projects)
        self.crypto = crypto
        self.fail = fail
        self.failure_output = failure_output
        self.builds = 0
        self.postgres = False

    def commands(self, word: str) -> list[list[str]]:
        return [call.args for call in self.calls if word in call.args]

    def __call__(self, args, *, cwd, env=None, timeout=120):
        args = [str(item) for item in args]
        self.calls.append(Call(args, Path(cwd), dict(env or {})))

        def done(code: int = 0, out: str = '', err: str = '') -> subprocess.CompletedProcess:
            return subprocess.CompletedProcess(args, code, out, err)

        if args[:3] == ['docker', 'compose', 'version']:
            return done(out='Docker Compose version v5.6.0\n')
        if args[:3] == ['docker', 'compose', 'ls']:
            return done(out=json.dumps(self.projects))
        if args[:3] == ['docker', 'volume', 'inspect']:
            return done() if args[3] in self.volumes else done(1, err='no such volume')
        if args[:3] == ['docker', 'image', 'inspect']:
            reference = args[-1]
            if reference not in self.images:
                return done(1, err=f'No such image: {reference}')
            digests = self.images[reference]
            return done(out=json.dumps(digests) + '|' + digests[0].split('@', 1)[1] + '\n')
        if args[:2] == ['docker', 'pull']:
            self.images[args[2]] = [f'{repository(args[2])}@{fake_digest(args[2])}']
            return done()
        if args[:2] == ['docker', 'compose'] and 'build' in args:
            if self.fail == 'build':
                return done(1, err=self.failure_output or 'build failed')
            self.builds += 1
            for tag in (env['TRUST_CI_API_IMAGE'], env['TRUST_CI_WORKER_IMAGE'], env['TRUST_CI_RUNNER_BUILD_TAG']):
                self.images[tag] = [f'{repository(tag)}@{fake_digest(tag + str(self.builds))}']
            return done(out='built\n')
        if args[:2] == ['docker', 'compose'] and 'up' in args:
            self.postgres = True
            return done()
        if args[:2] == ['docker', 'compose'] and 'migrate' in args:
            return done(out='{"status": "schema-applied", "applied": ["001"], "pending": []}\n')
        if args[:2] == ['docker', 'compose'] and 'ps' in args:
            rows = [{'Service': 'postgres', 'State': 'running', 'Health': 'healthy'}] if self.postgres else []
            return done(out=json.dumps(rows))
        if args[0] == 'bash' and args[1].endswith('postgres-integration.sh'):
            if self.fail == 'harness':
                return done(1, out=self.failure_output, err='FAILED (failures=1)')
            return done(out='Ran 12 tests\nOK\n')
        if args[1:3] == ['-c', 'import cryptography']:
            return done() if self.crypto else done(1, err='No module named cryptography')
        if 'keygen' in args:
            private = Path(args[args.index('--private') + 1])
            public = Path(args[args.index('--public') + 1])
            if args[0] == 'docker':
                host = Path(args[args.index('--volume') + 1].rsplit(':', 1)[0])
                private, public = host / private.name, host / public.name
            descriptor = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w') as handle:
                handle.write('-----BEGIN PRIVATE KEY-----\nci\n-----END PRIVATE KEY-----\n')
            public.write_text(public_pem(b'\x01' * 32), encoding='utf-8')
            return done(out=json.dumps({'key_id': '0123456789abcdef', 'private': str(private), 'public': str(public)}))
        raise AssertionError(f'unexpected command: {args}')


class TrustCiCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix='getzilla-trust-ci-')
        self.base = Path(self._tmp.name)
        self.trust = make_tree(self.base)
        self.lines: list[str] = []

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def tool(self, host: FakeHost, tokens: Tokens | None = None, which=lambda name: None) -> tcs.Bootstrap:
        return tcs.Bootstrap(self.trust, runner=host, token=tokens or Tokens(), which=which,
                             out=self.lines.append, python='python3')

    def init(self, host: FakeHost, tokens: Tokens | None = None, **options) -> int:
        return self.tool(host, tokens).init(**options)

    def output(self) -> str:
        return '\n'.join(self.lines)

    def snapshot(self) -> dict[str, bytes]:
        return {str(path.relative_to(self.trust)): path.read_bytes()
                for path in sorted(self.trust.rglob('*')) if path.is_file() and 'logs' not in path.parts}


class InitSecretsTests(TrustCiCase):
    def test_init_generates_every_machine_secret_and_never_prints_one(self) -> None:
        tokens = Tokens()
        self.assertEqual(self.init(FakeHost(), tokens), 0, self.output())
        self.assertEqual(len(tokens.issued), 7)  # admin, four roles, webhook secret, read token
        self.assertEqual(len(set(tokens.issued)), 7)
        text = self.output()
        for secret in tokens.issued:
            self.assertNotIn(secret, text)
            for log in (self.trust / 'runtime/logs').glob('*.log'):
                self.assertNotIn(secret, log.read_text(encoding='utf-8'))
        for _, target in tcs.ENV_FILES:
            path = self.trust / target
            self.assertTrue(path.is_file(), target)
            leftovers = [key for key, value in env_values(path).items() if tcs.PLACEHOLDER in value]
            expected = ['TRUST_CI_GITHUB_APP_ID', 'TRUST_CI_GITHUB_INSTALLATION_ID'] if target == 'env/worker.env' else []
            self.assertEqual(leftovers, expected, target)
            if POSIX:
                self.assertEqual(mode(path), 0o600, target)
        api = env_values(self.trust / 'env/api.env')
        self.assertIn(api['TRUST_CI_WEBHOOK_SECRET'], tokens.issued)
        self.assertIn(api['TRUST_CI_READ_TOKEN'], tokens.issued)

    def test_role_passwords_match_their_url_encoded_database_urls(self) -> None:
        self.assertEqual(self.init(FakeHost()), 0, self.output())
        postgres = env_values(self.trust / 'env/postgres.env')
        seen = {postgres['POSTGRES_PASSWORD']}
        for password_key, rel, url_key in tcs.ROLE_PASSWORDS:
            url = urlsplit(env_values(self.trust / rel)[url_key])
            self.assertEqual(unquote(url.password), postgres[password_key], rel)
            self.assertEqual(url.password, quote(postgres[password_key], safe=''))
            self.assertEqual(url.hostname, 'postgres')
            seen.add(postgres[password_key])
        self.assertEqual(len(seen), 5, 'the admin and every role must have their own password')

    def test_rerun_changes_nothing_and_generates_nothing(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        before = self.snapshot()
        builds, keygens = host.builds, len(host.commands('keygen'))
        self.assertEqual(self.init(host, Tokens(forbid=True)), 0, self.output())
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(host.builds, builds)
        self.assertEqual(len(host.commands('keygen')), keygens)

    def test_rerun_fills_only_what_is_missing(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        before = self.snapshot()
        shutil.copy2(self.trust / 'env/api.env.example', self.trust / 'env/api.env')
        tokens = Tokens()
        self.assertEqual(self.init(host, tokens), 0, self.output())
        self.assertEqual(len(tokens.issued), 2)  # only the webhook secret and the read token were missing
        api = env_values(self.trust / 'env/api.env')
        postgres = env_values(self.trust / 'env/postgres.env')
        self.assertEqual(unquote(urlsplit(api['TRUST_CI_DATABASE_URL']).password), postgres['TRUST_CI_API_DB_PASSWORD'])
        after = self.snapshot()
        for rel, data in before.items():
            if rel != 'env/api.env':
                self.assertEqual(after[rel], data, rel)

    def test_mismatched_existing_password_fails_closed_without_writing(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        api = self.trust / 'env/api.env'
        values = env_values(api)
        url = values['TRUST_CI_DATABASE_URL']
        stale = url.replace(urlsplit(url).password, 'stale-password-0000')
        api.write_text(api.read_text(encoding='utf-8').replace(url, stale), encoding='utf-8')
        before = self.snapshot()
        self.lines.clear()
        self.assertEqual(self.init(host, Tokens(forbid=True)), 1)
        self.assertEqual(self.snapshot(), before)
        self.assertIn('TRUST_CI_API_DB_PASSWORD', self.output())
        self.assertNotIn('stale-password-0000', self.output())
        self.assertFalse(host.commands('up')[1:], 'nothing may start after a refused secret')

    def test_new_database_passwords_are_refused_when_the_volume_exists(self) -> None:
        host = FakeHost(volumes={'adaptive-trust-ci_trust-ci-postgres'})
        self.assertEqual(self.init(host), 1)
        self.assertIn('adaptive-trust-ci_trust-ci-postgres', self.output())
        self.assertFalse((self.trust / 'env/postgres.env').exists())
        self.assertFalse(host.commands('up'))

    def test_public_url_fills_the_example_value_only(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host, public_url='https://ci.acme.test'), 0, self.output())
        common = env_values(self.trust / 'env/common.env')
        self.assertEqual(common['TRUST_CI_PUBLIC_BASE_URL'], 'https://ci.acme.test')
        self.assertEqual(self.init(host, public_url='https://ci.acme.test/'), 0, self.output())
        self.assertEqual(self.init(host, public_url='https://other.acme.test'), 1)
        self.assertEqual(self.init(host, public_url='http://ci.acme.test'), 1)
        self.assertEqual(env_values(self.trust / 'env/common.env')['TRUST_CI_PUBLIC_BASE_URL'], 'https://ci.acme.test')


class InitImageAndKeyTests(TrustCiCase):
    def test_images_are_built_with_the_build_override_and_pinned_by_digest(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        env = env_values(self.trust / '.env')
        self.assertEqual(env['TRUST_CI_POSTGRES_IMAGE'], 'postgres:17.6-bookworm@' + fake_digest('postgres:17.6-bookworm'))
        self.assertEqual(env['TRUST_CI_PYTHON_BASE_IMAGE'],
                         'python:3.12-slim-bookworm@' + fake_digest('python:3.12-slim-bookworm'))
        self.assertEqual(env['TRUST_CI_DIND_IMAGE'], 'docker:29-dind-rootless@' + fake_digest('docker:29-dind-rootless'))
        self.assertEqual(env['TRUST_CI_API_IMAGE'], 'adaptive-trust-ci-api@' + fake_digest(tcs.API_BUILD_TAG + '1'))
        self.assertEqual(env['TRUST_CI_WORKER_IMAGE'],
                         'adaptive-trust-ci-worker@' + fake_digest(tcs.WORKER_BUILD_TAG + '1'))
        runner_tag = env['TRUST_CI_RUNNER_BUILD_TAG']
        self.assertEqual(env['TRUST_CI_RUNNER_IMAGE'], f'{repository(runner_tag)}@' + fake_digest(runner_tag + '1'))
        for key in tcs.IMAGE_KEYS:
            self.assertRegex(env[key], tcs.IMMUTABLE_IMAGE.pattern)
        policy = json.loads((self.trust / 'runtime/policy.json').read_text(encoding='utf-8'))
        self.assertEqual(policy['sandbox']['image'], env['TRUST_CI_RUNNER_IMAGE'])
        [build] = host.commands('runner-image')
        self.assertEqual(build[build.index('-f') + 1:build.index('-f') + 4], ['compose.yaml', '-f', 'compose.build.yaml'])
        self.assertEqual(build[-6:], ['--profile', 'build', 'build', 'api', 'worker', 'runner-image'])
        build_env = next(call.env for call in host.calls if 'build' in call.args)
        self.assertEqual(build_env['TRUST_CI_API_IMAGE'], tcs.API_BUILD_TAG)
        self.assertEqual(build_env['TRUST_CI_WORKER_IMAGE'], tcs.WORKER_BUILD_TAG)

    def test_missing_base_images_are_pulled_once(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        pulls = sorted(call.args[2] for call in host.calls if call.args[:2] == ['docker', 'pull'])
        self.assertEqual(pulls, ['docker:29-dind-rootless', 'python:3.12-slim-bookworm'])

    def test_rebuild_repins_images_and_policy_but_keeps_every_secret(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        secrets_before = {rel: (self.trust / rel).read_bytes() for rel in ('env/api.env', 'env/postgres.env')}
        first = env_values(self.trust / '.env')['TRUST_CI_RUNNER_IMAGE']
        self.assertEqual(self.init(host, Tokens(forbid=True), rebuild=True), 0, self.output())
        second = env_values(self.trust / '.env')['TRUST_CI_RUNNER_IMAGE']
        self.assertNotEqual(first, second)
        policy = json.loads((self.trust / 'runtime/policy.json').read_text(encoding='utf-8'))
        self.assertEqual(policy['sandbox']['image'], second)
        for rel, data in secrets_before.items():
            self.assertEqual((self.trust / rel).read_bytes(), data)

    def test_policy_runner_conflict_fails_closed(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        path = self.trust / 'runtime/policy.json'
        policy = json.loads(path.read_text(encoding='utf-8'))
        policy['sandbox']['image'] = 'ghcr.io/acme/runner@sha256:' + 'b' * 64
        path.write_text(json.dumps(policy, indent=2) + '\n', encoding='utf-8')
        self.assertEqual(self.init(host, Tokens(forbid=True)), 1)
        self.assertIn('sandbox.image', self.output())
        self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['sandbox']['image'],
                         'ghcr.io/acme/runner@sha256:' + 'b' * 64)
        env_before = (self.trust / '.env').read_bytes()
        self.assertEqual(self.init(host, Tokens(forbid=True), rebuild=True), 1)
        self.assertEqual((self.trust / '.env').read_bytes(), env_before, 'a refused rebuild must keep the old pins')

    @unittest.skipUnless(POSIX, 'POSIX file modes')
    def test_ci_key_is_generated_once_by_keygen_with_0600(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        [keygen] = host.commands('keygen')
        self.assertEqual(keygen[:4], ['python3', '-m', 'adaptive_trust_ci.cli', 'keygen'])
        private = self.trust / 'runtime/trust-ci-signing-key.pem'
        self.assertEqual(Path(keygen[keygen.index('--private') + 1]), private)
        self.assertEqual(Path(keygen[keygen.index('--public') + 1]), self.trust / 'runtime/trust-ci-signing-key.pub.pem')
        self.assertEqual(mode(private), 0o600)
        call = next(c for c in host.calls if 'keygen' in c.args)
        self.assertEqual(call.env.get('PYTHONPATH'), str(self.trust / 'src'))
        self.assertIn('0123456789abcdef', self.output())
        self.assertEqual(self.init(host, Tokens(forbid=True)), 0, self.output())
        self.assertEqual(len(host.commands('keygen')), 1)

    def test_keygen_prefers_the_installed_tool(self) -> None:
        host = FakeHost()
        self.assertEqual(self.tool(host, which=lambda name: '/usr/local/bin/' + name).init(), 0, self.output())
        self.assertEqual(host.commands('keygen')[0][:2], ['/usr/local/bin/adaptive-trust-ci', 'keygen'])

    @unittest.skipUnless(POSIX, 'POSIX user ids')
    def test_keygen_falls_back_to_the_built_worker_image(self) -> None:
        host = FakeHost(crypto=False)
        self.assertEqual(self.init(host), 0, self.output())
        [keygen] = host.commands('keygen')
        worker = env_values(self.trust / '.env')['TRUST_CI_WORKER_IMAGE']
        self.assertEqual(keygen[:3], ['docker', 'run', '--rm'])
        self.assertEqual(keygen[keygen.index('--network') + 1], 'none')
        self.assertEqual(keygen[keygen.index('--user') + 1], f'{os.getuid()}:{os.getgid()}')
        self.assertEqual(keygen[keygen.index('keygen') - 1], worker)
        self.assertEqual(mode(self.trust / 'runtime/trust-ci-signing-key.pem'), 0o600)

    def test_the_agent_never_generates_a_human_key(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        for args in host.commands('keygen'):
            target = Path(args[args.index('--private') + 1])
            self.assertEqual(target.name, 'trust-ci-signing-key.pem')
        trust_store = json.loads((self.trust / 'runtime/trust-store.json').read_text(encoding='utf-8'))
        self.assertTrue(all(tcs.PLACEHOLDER in key['key_id'] for key in trust_store['keys']))


class InitDockerTests(TrustCiCase):
    def test_steps_run_in_order_postgres_migrate_harness(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        order = []
        for call in host.calls:
            for word in ('build', 'keygen', 'up', 'migrate', 'postgres-integration.sh'):
                if word in call.args or (word.endswith('.sh') and call.args[-1].endswith(word)):
                    order.append(word)
        self.assertEqual(order, ['build', 'keygen', 'up', 'migrate', 'postgres-integration.sh'])
        [up] = host.commands('up')
        self.assertEqual(up[-1], 'postgres')
        self.assertIn('--wait', up)
        self.assertEqual(up[up.index('--project-name') + 1], 'adaptive-trust-ci')
        [migrate] = host.commands('migrate')
        self.assertEqual(migrate[-3:], ['run', '--rm', 'migrate'])
        harness = next(c for c in host.calls if c.args[0] == 'bash')
        self.assertEqual(harness.cwd, self.base)
        env = env_values(self.trust / '.env')
        self.assertEqual(harness.env['TRUST_CI_POSTGRES_IMAGE'], env['TRUST_CI_POSTGRES_IMAGE'])
        self.assertEqual(harness.env['TRUST_CI_PYTHON_BASE_IMAGE'], env['TRUST_CI_PYTHON_BASE_IMAGE'])

    def test_skip_harness(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host, harness=False), 0, self.output())
        self.assertFalse([c for c in host.calls if c.args[0] == 'bash'])
        self.assertIn('skip', self.output())

    def test_existing_project_from_another_directory_is_refused(self) -> None:
        other = {'Name': 'adaptive-trust-ci', 'Status': 'running(4)', 'ConfigFiles': '/srv/other/trust-ci/compose.yaml'}
        host = FakeHost(projects=[other])
        self.assertEqual(self.init(host), 1)
        self.assertIn('--project-name', self.output())
        self.assertIn('/srv/other/trust-ci/compose.yaml', self.output())
        self.assertFalse((self.trust / '.env').exists())
        self.assertFalse(host.commands('up') or host.commands('build'))

    def test_the_same_project_from_this_directory_is_reused(self) -> None:
        ours = {'Name': 'adaptive-trust-ci', 'Status': 'running(1)', 'ConfigFiles': str(self.trust / 'compose.yaml')}
        self.assertEqual(self.init(FakeHost(projects=[ours])), 0, self.output())

    def test_custom_project_name_is_recorded_and_reused(self) -> None:
        host = FakeHost(projects=[{'Name': 'adaptive-trust-ci', 'ConfigFiles': '/srv/other/compose.yaml'}],
                        volumes={'adaptive-trust-ci_trust-ci-postgres'})
        self.assertEqual(self.init(host, project='tci-boot'), 0, self.output())
        self.assertEqual(env_values(self.trust / '.env')['COMPOSE_PROJECT_NAME'], 'tci-boot')
        for args in host.commands('compose'):
            if 'ls' not in args and 'version' not in args:
                self.assertEqual(args[args.index('--project-name') + 1], 'tci-boot', args)
        self.assertIn(['docker', 'volume', 'inspect', 'tci-boot_trust-ci-postgres'], [c.args for c in host.calls])
        self.assertEqual(self.init(host, Tokens(forbid=True)), 0, self.output())
        self.assertEqual(host.commands('up')[-1][host.commands('up')[-1].index('--project-name') + 1], 'tci-boot')
        self.assertEqual(self.init(host, project='another'), 1)
        self.assertEqual(self.init(host, project='Bad Name'), 1)

    def test_failure_output_is_redacted_and_logged(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host, harness=False), 0, self.output())
        secret = env_values(self.trust / 'env/api.env')['TRUST_CI_WEBHOOK_SECRET']
        password = env_values(self.trust / 'env/postgres.env')['TRUST_CI_API_DB_PASSWORD']
        host.fail, host.failure_output = 'harness', f'leak {secret} and {quote(password, safe="")}\n'
        self.lines.clear()
        self.assertEqual(self.init(host, Tokens(forbid=True)), 1)
        text = self.output()
        self.assertNotIn(secret, text)
        self.assertNotIn(password, text)
        self.assertIn('[REDACTED]', text)
        log = self.trust / 'runtime/logs/init-harness.log'
        self.assertTrue(log.is_file())
        self.assertNotIn(secret, log.read_text(encoding='utf-8'))
        if POSIX:
            self.assertEqual(mode(log), 0o600)

    def test_docker_without_compose_v2_fails_before_writing(self) -> None:
        def no_docker(args, *, cwd, env=None, timeout=120):
            return subprocess.CompletedProcess(args, 127, '', 'command not found: docker')
        tool = tcs.Bootstrap(self.trust, runner=no_docker, token=Tokens(), which=lambda name: None,
                             out=self.lines.append, python='python3')
        self.assertEqual(tool.init(), 1)
        self.assertIn('Compose v2', self.output())
        self.assertFalse((self.trust / '.env').exists())


class ChecklistTests(TrustCiCase):
    def test_init_ends_with_exactly_the_three_human_steps(self) -> None:
        self.assertEqual(self.init(FakeHost()), 0, self.output())
        text = self.output()
        checklist = text[text.index('HUMAN STEPS'):]
        self.assertIn('1. GitHub App', checklist)
        self.assertIn('2. Human approval key', checklist)
        self.assertIn('3. Trust the public key', checklist)
        self.assertNotIn('4.', checklist)
        self.assertIn("sed -n 's/^TRUST_CI_WEBHOOK_SECRET=//p'", checklist)
        self.assertIn('getzilla trust-ci github-app', checklist)
        self.assertIn('getzilla trust-ci trust-key', checklist)
        self.assertIn('own workstation', checklist)
        self.assertIn('--public-url', checklist)

    def test_completed_human_steps_leave_the_checklist(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host, public_url='https://ci.acme.test'), 0, self.output())
        tool = self.tool(host)
        key = self.base / 'app.pem'
        key.write_bytes(RSA_KEY)
        self.assertEqual(tool.github_app(app_id='12345', installation_id='auto', private_key=key), 0, self.output())
        pub = self.base / 'owner.pub.pem'
        pub.write_text(public_pem(b'\x07' * 32), encoding='utf-8')
        self.assertEqual(tool.trust_key(public_key=pub, actor='owner'), 0, self.output())
        self.lines.clear()
        self.assertEqual(self.init(host, Tokens(forbid=True)), 0, self.output())
        self.assertIn('No human steps are pending', self.output())


class StatusTests(TrustCiCase):
    def status(self, host: FakeHost, **options) -> tuple[int, dict]:
        self.lines.clear()
        code = self.tool(host).status(as_json=True, **options)
        return code, json.loads(self.output())

    def states(self, report: dict) -> dict[str, str]:
        return {item['name']: item['state'] for item in report['checks']}

    def test_status_before_init_says_what_to_run(self) -> None:
        code, report = self.status(FakeHost())
        self.assertEqual(code, tcs.EXIT_PENDING)
        self.assertEqual(self.states(report)['env-files'], 'todo')
        self.assertFalse(report['ready'])

    def test_status_after_init_waits_only_on_human_steps(self) -> None:
        host = FakeHost()
        tokens = Tokens()
        self.assertEqual(self.init(host, tokens), 0, self.output())
        code, report = self.status(host)
        self.assertEqual(code, tcs.EXIT_PENDING)
        states = self.states(report)
        todo = sorted(name for name, state in states.items() if state == 'todo')
        self.assertEqual(todo, ['github-app', 'holdout-source', 'public-url', 'trust-store'])
        self.assertFalse([name for name, state in states.items() if state == 'fail'], report)
        self.assertEqual(states['postgres'], 'ok')
        self.assertEqual(states['key-split'], 'ok')
        self.assertEqual(states['secrets'], 'ok')
        self.assertEqual([step['number'] for step in report['human_steps']], [1, 2, 3])
        for secret in tokens.issued:
            self.assertNotIn(secret, self.output())

    def test_status_is_ready_after_the_human_steps(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host, public_url='https://ci.acme.test'), 0, self.output())
        holdout = self.base / 'holdout'
        holdout.mkdir()
        env = self.trust / '.env'
        env.write_text(env.read_text(encoding='utf-8').replace('/srv/adaptive-trust-ci/holdout', str(holdout)),
                       encoding='utf-8')
        key = self.base / 'app.pem'
        key.write_bytes(RSA_KEY)
        tool = self.tool(host)
        self.assertEqual(tool.github_app(app_id='12345', installation_id='67890', private_key=key), 0, self.output())
        pub = self.base / 'owner.pub.pem'
        pub.write_text(public_pem(b'\x07' * 32), encoding='utf-8')
        self.assertEqual(tool.trust_key(public_key=pub, actor='owner'), 0, self.output())
        code, report = self.status(host)
        self.assertEqual(code, 0, report)
        self.assertTrue(report['ready'])
        self.assertEqual(report['human_steps'], [])

    def test_status_fails_on_password_mismatch_and_key_split_violation(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        postgres = self.trust / 'env/postgres.env'
        value = env_values(postgres)['TRUST_CI_WORKER_DB_PASSWORD']
        postgres.write_text(postgres.read_text(encoding='utf-8').replace(value, 'changed-by-hand-0000'), encoding='utf-8')
        api = self.trust / 'env/api.env'
        api.write_text(api.read_text(encoding='utf-8') + 'TRUST_CI_GITHUB_APP_ID=1\n', encoding='utf-8')
        code, report = self.status(host)
        self.assertEqual(code, 1)
        states = self.states(report)
        self.assertEqual(states['secrets'], 'fail')
        self.assertEqual(states['key-split'], 'fail')
        self.assertNotIn('changed-by-hand-0000', self.output())

    def test_human_text_status(self) -> None:
        host = FakeHost()
        self.assertEqual(self.init(host), 0, self.output())
        self.lines.clear()
        self.assertEqual(self.tool(host).status(), tcs.EXIT_PENDING)
        self.assertIn('HUMAN STEPS', self.output())
        self.assertIn('[todo] github-app', self.output())


class GithubAppTests(TrustCiCase):
    def setUp(self) -> None:
        super().setUp()
        self.assertEqual(self.init(FakeHost(), harness=False), 0, self.output())
        self.key = self.base / 'downloaded.pem'
        self.key.write_bytes(RSA_KEY)

    def test_writes_worker_env_and_key_only(self) -> None:
        api_before = (self.trust / 'env/api.env').read_bytes()
        self.lines.clear()
        tool = self.tool(FakeHost())
        self.assertEqual(tool.github_app(app_id='12345', installation_id='auto', private_key=self.key), 0, self.output())
        worker = env_values(self.trust / 'env/worker.env')
        self.assertEqual(worker['TRUST_CI_GITHUB_APP_ID'], '12345')
        self.assertEqual(worker['TRUST_CI_GITHUB_INSTALLATION_ID'], 'auto')
        installed = self.trust / 'runtime/github-app-private-key.pem'
        self.assertEqual(installed.read_bytes(), RSA_KEY)
        if POSIX:
            self.assertEqual(mode(installed), 0o600)
            self.assertEqual(mode(self.trust / 'env/worker.env'), 0o600)
        self.assertEqual((self.trust / 'env/api.env').read_bytes(), api_before)
        for name in WORKER_ONLY:
            self.assertNotIn(name, env_values(self.trust / 'env/api.env'))
        self.assertNotIn('MIIEdGVzdA', self.output())
        self.assertEqual(tool.github_app(app_id='12345', installation_id='auto', private_key=self.key), 0, self.output())

    def test_rejects_bad_input(self) -> None:
        tool = self.tool(FakeHost())
        public = self.base / 'public.pem'
        public.write_text(public_pem(b'\x02' * 32), encoding='utf-8')
        encrypted = self.base / 'encrypted.pem'
        encrypted.write_bytes(b'-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n')
        self.assertEqual(tool.github_app(app_id='12345', installation_id='1', private_key=public), 1)
        self.assertEqual(tool.github_app(app_id='12345', installation_id='1', private_key=encrypted), 1)
        self.assertEqual(tool.github_app(app_id='abc', installation_id='1', private_key=self.key), 1)
        self.assertEqual(tool.github_app(app_id='12345', installation_id='-1', private_key=self.key), 1)
        self.assertFalse((self.trust / 'runtime/github-app-private-key.pem').exists())
        self.assertIn(tcs.PLACEHOLDER, env_values(self.trust / 'env/worker.env')['TRUST_CI_GITHUB_APP_ID'])

    def test_refuses_to_replace_a_different_app_or_key(self) -> None:
        tool = self.tool(FakeHost())
        self.assertEqual(tool.github_app(app_id='12345', installation_id='1', private_key=self.key), 0, self.output())
        self.assertEqual(tool.github_app(app_id='99999', installation_id='1', private_key=self.key), 1)
        other = self.base / 'other.pem'
        other.write_bytes(RSA_KEY.replace(b'MIIEdGVzdA==', b'MIIEb3RoZXI='))
        self.assertEqual(tool.github_app(app_id='12345', installation_id='1', private_key=other), 1)
        self.assertEqual((self.trust / 'runtime/github-app-private-key.pem').read_bytes(), RSA_KEY)

    def test_docker_created_directory_is_reported(self) -> None:
        (self.trust / 'runtime/github-app-private-key.pem').mkdir()
        self.assertEqual(self.tool(FakeHost()).github_app(app_id='1', installation_id='1', private_key=self.key), 1)
        self.assertIn('directory', self.output())


class TrustKeyTests(TrustCiCase):
    def setUp(self) -> None:
        super().setUp()
        self.assertEqual(self.init(FakeHost(), harness=False), 0, self.output())
        self.raw = bytes(range(32))
        self.pub = self.base / 'owner.pub.pem'
        self.pub.write_text(public_pem(self.raw), encoding='utf-8')
        self.key_id = hashlib.sha256(self.raw).hexdigest()[:16]

    def store(self) -> dict:
        return json.loads((self.trust / 'runtime/trust-store.json').read_text(encoding='utf-8'))

    def test_adds_the_key_with_its_computed_key_id_replacing_the_placeholder(self) -> None:
        tool = self.tool(FakeHost())
        self.assertEqual(tool.trust_key(public_key=self.pub, actor='owner', key_id=self.key_id), 0, self.output())
        [entry] = self.store()['keys']
        self.assertEqual(entry['key_id'], self.key_id)
        self.assertEqual(entry['actor'], 'owner')
        self.assertEqual(entry['scopes'], list(tcs.DEFAULT_SCOPES))
        self.assertIsNone(entry['revoked_at'])
        self.assertEqual(entry['public_key_pem'], public_pem(self.raw))
        if POSIX:
            self.assertEqual(mode(self.trust / 'runtime/trust-store.json'), 0o644)
        self.assertEqual(tool.trust_key(public_key=self.pub, actor='owner'), 0, self.output())
        self.assertEqual(len(self.store()['keys']), 1)

    def test_matches_the_trust_ci_service_parser(self) -> None:
        try:
            sys.path.insert(0, str(REAL / 'src'))
            from adaptive_trust_ci.signing import TrustStore
        except ImportError as exc:  # the service dependencies are optional on a developer machine
            self.skipTest(f'trust-ci dependencies are not installed: {exc}')
        finally:
            sys.path.remove(str(REAL / 'src'))
        self.assertEqual(self.tool(FakeHost()).trust_key(public_key=self.pub, actor='owner'), 0, self.output())
        store = TrustStore.from_dict(self.store())
        self.assertEqual(list(store.keys), [self.key_id])

    def test_rejects_a_private_key_or_a_wrong_key_id(self) -> None:
        tool = self.tool(FakeHost())
        private = self.base / 'owner.pem'
        private.write_text('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n', encoding='utf-8')
        self.assertEqual(tool.trust_key(public_key=private, actor='owner'), 1)
        self.assertIn('private key', self.output())
        self.assertNotIn('AAAA', self.output())
        self.assertEqual(tool.trust_key(public_key=self.pub, actor='owner', key_id='ffffffffffffffff'), 1)
        self.assertEqual(tool.trust_key(public_key=self.pub, actor='bad actor'), 1)
        rsa = self.base / 'rsa.pub.pem'
        rsa.write_text('-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQ==\n-----END PUBLIC KEY-----\n', encoding='utf-8')
        self.assertEqual(tool.trust_key(public_key=rsa, actor='owner'), 1)
        self.assertTrue(all(tcs.PLACEHOLDER in key['key_id'] for key in self.store()['keys']))


class CommandTests(unittest.TestCase):
    def test_getzilla_dispatches_trust_ci(self) -> None:
        import getzilla_cli as cli

        self.assertEqual(cli.COMMANDS['trust-ci'][0], 'getzilla_trust_ci.py')
        proc = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_cli.py'), 'trust-ci', '--help'],
                              capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for name in ('init', 'status', 'github-app', 'trust-key'):
            self.assertIn(name, proc.stdout)

    def test_missing_trust_ci_directory_is_a_usage_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_trust_ci.py'), '--trust-ci-dir', tmp,
                                   'status'], capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(proc.returncode, 2)
        self.assertIn('compose.yaml', proc.stderr)

    def test_quickstart_documents_the_one_command(self) -> None:
        text = (ROOT / 'QUICKSTART.md').read_text(encoding='utf-8')
        section = text[text.index('## Operator: Trust CI host'):]
        for needle in ('getzilla trust-ci init', 'getzilla trust-ci status', 'getzilla trust-ci github-app',
                       'getzilla trust-ci trust-key', '--project-name'):
            self.assertIn(needle, section)


if __name__ == '__main__':
    unittest.main()
