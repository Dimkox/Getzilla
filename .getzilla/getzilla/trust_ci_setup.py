"""One-command bootstrap of the self-hosted Trust CI host (`getzilla trust-ci`).

`init` does every machine-side step and is safe to re-run. It creates the untracked env files from
their templates, generates each missing machine secret, pins the base and built images by digest,
creates the CI attestation key, starts PostgreSQL, applies the migrations and runs the live
PostgreSQL harness. It never overwrites a secret, a key or a pin that exists, and it never prints a
secret value. The steps that only a human can do (the GitHub App, the human approval key and its
trust-store entry) end the run as an exact checklist. `status` reports the same state read-only.

The key split stays as documented in trust-ci/README.md: the API never receives the GitHub App ID,
installation ID or private key, and the worker never receives the webhook secret or the trust store.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator, Mapping, Protocol
from urllib.parse import quote, unquote, urlsplit

from .util import atomic_write_text, run as run_command

DEFAULT_PROJECT = 'adaptive-trust-ci'
PLACEHOLDER = 'REPLACE_WITH_'
EXAMPLE_PUBLIC_URL = 'https://ci.example.com'
API_BUILD_TAG = 'adaptive-trust-ci-api:local'
WORKER_BUILD_TAG = 'adaptive-trust-ci-worker:local'
DEFAULT_RUNNER_BUILD_TAG = 'adaptive-trust-ci-runner:2.1.0'
WORKER_UID = 10001
DEFAULT_SCOPES = ('governance', 'database', 'production')
EXIT_READY, EXIT_FAILED, EXIT_PENDING = 0, 1, 3

ENV_FILES = (
    ('.env.example', '.env'),
    ('env/common.env.example', 'env/common.env'),
    ('env/api.env.example', 'env/api.env'),
    ('env/worker.env.example', 'env/worker.env'),
    ('env/migration.env.example', 'env/migration.env'),
    ('env/postgres.env.example', 'env/postgres.env'),
    ('env/backup.env.example', 'env/backup.env'),
)
# Role password in env/postgres.env, the role's env file, and the URL that must carry the same password.
ROLE_PASSWORDS = (
    ('TRUST_CI_API_DB_PASSWORD', 'env/api.env', 'TRUST_CI_DATABASE_URL'),
    ('TRUST_CI_WORKER_DB_PASSWORD', 'env/worker.env', 'TRUST_CI_DATABASE_URL'),
    ('TRUST_CI_MIGRATOR_DB_PASSWORD', 'env/migration.env', 'TRUST_CI_DATABASE_URL'),
    ('TRUST_CI_BACKUP_DB_PASSWORD', 'env/backup.env', 'TRUST_CI_BACKUP_DATABASE_URL'),
)
ADMIN_ENV_KEY = 'POSTGRES_PASSWORD'
API_SECRETS = ('TRUST_CI_WEBHOOK_SECRET', 'TRUST_CI_READ_TOKEN')
SECRET_KEYS = frozenset({ADMIN_ENV_KEY, *API_SECRETS, *(item[0] for item in ROLE_PASSWORDS)})
GITHUB_APP_KEYS = ('TRUST_CI_GITHUB_APP_ID', 'TRUST_CI_GITHUB_INSTALLATION_ID')
# The documented key split: what each service must never see.
API_FORBIDDEN = (*GITHUB_APP_KEYS, 'TRUST_CI_GITHUB_APP_PRIVATE_KEY_PATH', 'TRUST_CI_SIGNING_KEY_PATH')
WORKER_FORBIDDEN = ('TRUST_CI_WEBHOOK_SECRET', 'TRUST_CI_READ_TOKEN', 'TRUST_CI_TRUST_STORE_PATH')
BASE_IMAGE_KEYS = ('TRUST_CI_PYTHON_BASE_IMAGE', 'TRUST_CI_POSTGRES_IMAGE', 'TRUST_CI_DIND_IMAGE')
BUILT_IMAGE_KEYS = ('TRUST_CI_API_IMAGE', 'TRUST_CI_WORKER_IMAGE', 'TRUST_CI_RUNNER_IMAGE')
IMAGE_KEYS = (*BASE_IMAGE_KEYS, *BUILT_IMAGE_KEYS)
IMMUTABLE_IMAGE = re.compile(r'^(?:sha256:[0-9a-f]{64}|.+@sha256:[0-9a-f]{64})$')
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
PROJECT_NAME = re.compile(r'^[a-z0-9][a-z0-9_-]*$')
POSITIVE_ID = re.compile(r'^[1-9][0-9]{0,18}$')
ACTOR = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$')
INSPECT_FORMAT = '{{json .RepoDigests}}|{{.Id}}'
ED25519_SPKI_PREFIX = bytes.fromhex('302a300506032b6570032100')
CI_PRIVATE_KEY = 'runtime/trust-ci-signing-key.pem'
CI_PUBLIC_KEY = 'runtime/trust-ci-signing-key.pub.pem'
APP_PRIVATE_KEY = 'runtime/github-app-private-key.pem'
POLICY = 'runtime/policy.json'
TRUST_STORE = 'runtime/trust-store.json'


class SetupError(RuntimeError):
    """A step cannot continue. Messages name files and keys, never secret values."""


class Runner(Protocol):
    def __call__(self, args: list[str], *, cwd: Path, env: Mapping[str, str] | None = None,
                 timeout: int = 120) -> subprocess.CompletedProcess[str]: ...


def system_runner(args: list[str], *, cwd: Path, env: Mapping[str, str] | None = None,
                  timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return run_command(list(args), cwd=cwd, env=dict(env) if env else None, timeout=timeout, errors='replace')


def read_env_text(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and '=' in stripped:
            key, value = stripped.split('=', 1)
            values[key.strip()] = value.strip()
    return values


def read_env(path: Path) -> dict[str, str]:
    return read_env_text(path.read_text(encoding='utf-8'))


def render_env(text: str, updates: Mapping[str, str]) -> str:
    """`text` with each updated key's value replaced in place; new keys are appended."""
    lines, seen = [], set()
    for line in text.splitlines():
        stripped = line.strip()
        key = stripped.split('=', 1)[0].strip() if '=' in stripped and not stripped.startswith('#') else None
        if key in updates:
            lines.append(f'{key}={updates[key]}')
            seen.add(key)
        else:
            lines.append(line)
    lines += [f'{key}={value}' for key, value in updates.items() if key not in seen]
    return '\n'.join(lines) + '\n'


def missing(value: str | None) -> bool:
    return not value or PLACEHOLDER in value


def url_password(url: str) -> str | None:
    if missing(url):
        return None
    try:
        password = urlsplit(url).password
    except ValueError:
        return None
    return unquote(password) if password else None


def fill_url_password(url: str, password: str) -> str:
    filled, count = re.subn(r'REPLACE_WITH_[A-Z0-9_]+', lambda _: quote(password, safe=''), url, count=1)
    if not count:
        raise SetupError('a database URL has neither a password nor a REPLACE_WITH_ placeholder')
    return filled


def image_repository(reference: str) -> str:
    """`postgres:17.6-bookworm` -> `postgres`; a registry port is kept."""
    head, _, last = reference.split('@', 1)[0].rpartition('/')
    name = last.split(':', 1)[0]
    return f'{head}/{name}' if head else name


def ed25519_key_id(pem: str) -> str | None:
    """The Trust CI key_id (first 16 hex of SHA-256 over the raw key) of an Ed25519 public key PEM."""
    match = re.search(r'-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----', pem, re.S)
    if not match:
        return None
    try:
        der = base64.b64decode(''.join(match.group(1).split()), validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(der) != len(ED25519_SPKI_PREFIX) + 32 or not der.startswith(ED25519_SPKI_PREFIX):
        return None
    return hashlib.sha256(der[len(ED25519_SPKI_PREFIX):]).hexdigest()[:16]


def write_private(path: Path, text: str) -> None:
    atomic_write_text(path, text)  # created 0600 by mkstemp, then renamed into place
    os.chmod(path, 0o600)


def write_public(path: Path, text: str) -> None:
    # The API and worker containers run as uid 10001 and read these through bind mounts.
    atomic_write_text(path, text)
    os.chmod(path, 0o644)


def write_new_private_bytes(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def file_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


@contextlib.contextmanager
def private_umask() -> Iterator[None]:
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


class Bootstrap:
    def __init__(self, trust: Path, *, runner: Runner = system_runner, token: Callable[[], str] | None = None,
                 which: Callable[[str], str | None] = shutil.which, out: Callable[[str], None] = print,
                 python: str = sys.executable) -> None:
        self.trust = Path(trust).resolve()
        self.runner = runner
        self.token = token or (lambda: secrets.token_urlsafe(32))
        self.which = which
        self.out = out
        self.python = python

    # ----- shared helpers -------------------------------------------------------------------

    def path(self, rel: str) -> Path:
        return self.trust / rel

    def env(self, rel: str) -> dict[str, str]:
        path = self.path(rel)
        return read_env(path) if path.is_file() else {}

    def secret_values(self) -> set[str]:
        found: set[str] = set()
        for _, rel in ENV_FILES:
            for key, value in self.env(rel).items():
                candidates = [value] if key in SECRET_KEYS and not missing(value) else []
                if key.endswith('DATABASE_URL') and url_password(value):
                    candidates.append(url_password(value) or '')
                for item in candidates:
                    found.update({item, quote(item, safe='')})
        return {item for item in found if len(item) >= 8}

    def redact(self, text: str) -> str:
        for value in sorted(self.secret_values(), key=len, reverse=True):
            text = text.replace(value, '[REDACTED]')
        return text

    def report(self, state: str, name: str, detail: str) -> None:
        self.out(self.redact(f'[{state}] {name}: {detail}'))

    def compose(self, project: str, *extra: str) -> list[str]:
        return ['docker', 'compose', '--project-name', project, '-f', 'compose.yaml', *extra]

    def step(self, name: str, args: list[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None,
             timeout: int = 120) -> subprocess.CompletedProcess[str]:
        """Run one host command; keep its redacted output under runtime/logs/ and fail with its tail."""
        proc = self.runner(args, cwd=cwd or self.trust, env=env, timeout=timeout)
        output = self.redact(f'$ {" ".join(args)}\n{proc.stdout or ""}{proc.stderr or ""}')
        logs = self.path('runtime/logs')
        logs.mkdir(parents=True, exist_ok=True)
        write_private(logs / f'init-{name}.log', output if output.endswith('\n') else output + '\n')
        if proc.returncode != 0:
            tail = '\n'.join(output.strip().splitlines()[-25:])
            raise SetupError(f'{name} failed with exit code {proc.returncode}; full log: '
                             f'trust-ci/runtime/logs/init-{name}.log\n{tail}')
        return proc

    def resolve_project(self, requested: str | None) -> str:
        current = self.env('.env').get('COMPOSE_PROJECT_NAME')
        if requested and current and requested != current:
            raise SetupError(f'.env already sets COMPOSE_PROJECT_NAME={current}; refusing to move this deployment to '
                             f'{requested}')
        project = requested or current or DEFAULT_PROJECT
        if not PROJECT_NAME.fullmatch(project):
            raise SetupError('a project name has lowercase letters, digits, "-" and "_" only, and starts with a '
                             'letter or digit')
        return project

    # ----- init -----------------------------------------------------------------------------

    def init(self, *, project: str | None = None, public_url: str | None = None, rebuild: bool = False,
             harness: bool = True) -> int:
        name = 'preflight'
        try:
            self.check_tree()
            self.check_docker()
            project = self.resolve_project(project)
            self.guard_project(project)
            self.report('ok', name, f'Docker Compose v2; compose project {project}')
            steps: list[tuple[str, Callable[[], str]]] = [
                ('env files', lambda: self.prepare_env(project, public_url)),
                ('runtime', self.prepare_runtime),
                ('base images', self.pin_base_images),
                ('images', lambda: self.build_and_pin(project, rebuild)),
                ('CI attestation key', self.ensure_ci_key),
                ('postgres', lambda: self.start_postgres(project)),
                ('migrate', lambda: self.migrate(project)),
            ]
            if harness:
                steps.append(('live harness', self.run_harness))
            for name, action in steps:
                self.report('ok', name, action())
            if not harness:
                self.report('skip', 'live harness', 'skipped by --skip-harness')
        except SetupError as exc:
            self.report('FAIL', name, str(exc))
            self.out('Nothing that existed was overwritten. Fix the cause, then run `getzilla trust-ci init` again.')
            return EXIT_FAILED
        for line in self.checklist():
            self.out(line)
        return EXIT_READY

    def check_tree(self) -> None:
        needed = ['compose.yaml', 'compose.build.yaml', 'scripts/postgres-integration.sh',
                  'config/policy.example.json', 'config/trust-store.example.json', *(item[0] for item in ENV_FILES)]
        absent = [rel for rel in needed if not self.path(rel).is_file()]
        if absent:
            raise SetupError(f'{self.trust} is not a complete trust-ci/ directory; missing: {", ".join(absent)}')

    def check_docker(self) -> None:
        proc = self.runner(['docker', 'compose', 'version'], cwd=self.trust, timeout=60)
        if proc.returncode != 0:
            raise SetupError('Docker Engine with Compose v2 is required on the Trust CI host '
                             '(`docker compose version` failed)')

    def guard_project(self, project: str) -> None:
        """Refuse a compose project of the same name that runs from another directory."""
        proc = self.runner(['docker', 'compose', 'ls', '--all', '--format', 'json'], cwd=self.trust, timeout=60)
        if proc.returncode != 0:
            raise SetupError('`docker compose ls` failed; cannot prove that the project name is free')
        try:
            entries = json.loads(proc.stdout or '[]') or []
        except json.JSONDecodeError as exc:
            raise SetupError('`docker compose ls` returned unreadable output') from exc
        ours = (self.trust / 'compose.yaml').resolve()
        for entry in entries:
            if not isinstance(entry, dict) or entry.get('Name') != project:
                continue
            files = [Path(item).resolve() for item in str(entry.get('ConfigFiles') or '').split(',') if item]
            if ours not in files:
                raise SetupError(f"compose project '{project}' already runs from {entry.get('ConfigFiles')}. That is "
                                 'another deployment; init does not touch it. Choose a new name with '
                                 '--project-name <name>.')

    def prepare_env(self, project: str, public_url: str | None) -> str:
        texts: dict[str, str] = {}
        created: list[str] = []
        for template, target in ENV_FILES:
            path = self.path(target)
            if path.is_file():
                texts[target] = path.read_text(encoding='utf-8')
            else:
                texts[target] = self.path(template).read_text(encoding='utf-8')
                created.append(target)
        values = {rel: read_env_text(text) for rel, text in texts.items()}
        updates: dict[str, dict[str, str]] = {rel: {} for rel in texts}
        generated: list[str] = []
        new_database_secrets: list[str] = []
        postgres = values['env/postgres.env']

        for password_key, rel, url_key in ROLE_PASSWORDS:
            stored = None if missing(postgres.get(password_key)) else postgres[password_key]
            url = values[rel].get(url_key, '')
            in_url = url_password(url)
            if stored and in_url and stored != in_url:
                raise SetupError(f'{password_key} in env/postgres.env differs from the password in {rel} {url_key}. '
                                 'init never overwrites a secret; make them equal by hand.')
            password = stored or in_url
            if password is None:
                password = self.token()
                generated.append(password_key)
                new_database_secrets.append(password_key)
            if not stored:
                updates['env/postgres.env'][password_key] = password
            if not in_url:
                updates[rel][url_key] = fill_url_password(url, password)
        if missing(postgres.get(ADMIN_ENV_KEY)):
            updates['env/postgres.env'][ADMIN_ENV_KEY] = self.token()
            generated.append(ADMIN_ENV_KEY)
            new_database_secrets.append(ADMIN_ENV_KEY)
        for key in API_SECRETS:
            if missing(values['env/api.env'].get(key)):
                updates['env/api.env'][key] = self.token()
                generated.append(key)

        if public_url is not None:
            wanted = self.valid_public_url(public_url)
            current = values['env/common.env'].get('TRUST_CI_PUBLIC_BASE_URL', '')
            if missing(current) or current.rstrip('/') == EXAMPLE_PUBLIC_URL:
                updates['env/common.env']['TRUST_CI_PUBLIC_BASE_URL'] = wanted
            elif current.rstrip('/') != wanted:
                raise SetupError(f'env/common.env already sets TRUST_CI_PUBLIC_BASE_URL={current}; edit it by hand to '
                                 'change it')
        if project != DEFAULT_PROJECT and values['.env'].get('COMPOSE_PROJECT_NAME') != project:
            updates['.env']['COMPOSE_PROJECT_NAME'] = project

        volume = f'{project}_trust-ci-postgres'
        if new_database_secrets and self.volume_exists(volume):
            raise SetupError(f'Docker volume {volume} is already initialized, but {", ".join(new_database_secrets)} '
                             'would be new; the database roles keep their old passwords. Restore the previous '
                             'env/postgres.env, or remove the volume on purpose.')

        written = []
        for rel, text in texts.items():
            path = self.path(rel)
            if rel in created or updates[rel]:
                path.parent.mkdir(parents=True, exist_ok=True)
                write_private(path, render_env(text, updates[rel]))
                written.append(rel)
            elif os.name != 'nt' and file_mode(path) & 0o077:
                os.chmod(path, 0o600)
                written.append(f'{rel} (mode 0600)')
        detail = (f'created {len(created)}, updated {len(written) - len(created)}; '
                  f'generated {len(generated)} secret(s)')
        if generated:
            detail += f' ({", ".join(sorted(generated))}; values are not printed)'
        return detail if written else 'complete; nothing was missing'

    @staticmethod
    def valid_public_url(value: str) -> str:
        url = value.strip().rstrip('/')
        parts = urlsplit(url)
        if parts.scheme != 'https' or not parts.hostname or parts.path or parts.query:
            raise SetupError('--public-url must be an https://host[:port] address (the API is behind TLS)')
        return url

    def volume_exists(self, name: str) -> bool:
        return self.runner(['docker', 'volume', 'inspect', name], cwd=self.trust, timeout=60).returncode == 0

    def prepare_runtime(self) -> str:
        self.path('runtime/control').mkdir(parents=True, exist_ok=True)
        created = []
        for example, target in (('config/policy.example.json', POLICY),
                                ('config/trust-store.example.json', TRUST_STORE)):
            if not self.path(target).exists():
                write_public(self.path(target), self.path(example).read_text(encoding='utf-8'))
                created.append(target)
        return f'created {", ".join(created)}' if created else 'policy and trust store exist'

    def image_digest(self, reference: str) -> str | None:
        """`name@sha256:...` of a local image, or its bare content id when the store has no repo digest."""
        proc = self.runner(['docker', 'image', 'inspect', '--format', INSPECT_FORMAT, reference],
                           cwd=self.trust, timeout=60)
        if proc.returncode != 0:
            return None
        listed, _, image_id = (proc.stdout or '').strip().partition('|')
        try:
            digests = json.loads(listed or '[]') or []
        except json.JSONDecodeError:
            digests = []
        repository = image_repository(reference)
        for item in digests:
            name, _, digest = str(item).partition('@')
            if name == repository and DIGEST.fullmatch(digest):
                return f'{name}@{digest}'
        return image_id if DIGEST.fullmatch(image_id) else None

    def pin_base_images(self) -> str:
        env = self.env('.env')
        updates: dict[str, str] = {}
        for key in BASE_IMAGE_KEYS:
            value = env.get(key, '')
            if not missing(value) and IMMUTABLE_IMAGE.fullmatch(value):
                continue
            reference = value.split('@', 1)[0]
            if not reference:
                raise SetupError(f'.env {key} names no image')
            found = self.image_digest(reference)
            if found is None or '@' not in found:
                self.step(f'pull-{image_repository(reference).rsplit("/", 1)[-1]}', ['docker', 'pull', reference],
                          timeout=1800)
                found = self.image_digest(reference)
            if found is None or '@' not in found:
                raise SetupError(f'{reference} has no registry digest after `docker pull`')
            updates[key] = f'{reference}@{found.split("@", 1)[1]}'
        if not updates:
            return 'python, postgres and dind base images already pinned'
        write_private(self.path('.env'), render_env(self.path('.env').read_text(encoding='utf-8'), updates))
        return 'pinned ' + ', '.join(f'{key}={value}' for key, value in updates.items())

    def build_and_pin(self, project: str, rebuild: bool) -> str:
        env = self.env('.env')
        pinned = all(not missing(env.get(key)) and IMMUTABLE_IMAGE.fullmatch(env.get(key, '')) for key in BUILT_IMAGE_KEYS)
        if pinned and not rebuild:
            policy = self.sync_policy_runner(env['TRUST_CI_RUNNER_IMAGE'], previous=None)
            return f'api, worker and runner already pinned (--rebuild re-pins them); policy {policy}'
        runner_tag = env.get('TRUST_CI_RUNNER_BUILD_TAG') or DEFAULT_RUNNER_BUILD_TAG
        overrides = {'TRUST_CI_API_IMAGE': API_BUILD_TAG, 'TRUST_CI_WORKER_IMAGE': WORKER_BUILD_TAG,
                     'TRUST_CI_RUNNER_BUILD_TAG': runner_tag}
        self.out('[..] images: building api, worker and runner; the first build takes several minutes')
        self.step('build', self.compose(project, '-f', 'compose.build.yaml', '--profile', 'build', 'build', 'api',
                                        'worker', 'runner-image'), env=overrides, timeout=3600)
        pins = {}
        for key, tag in (('TRUST_CI_API_IMAGE', API_BUILD_TAG), ('TRUST_CI_WORKER_IMAGE', WORKER_BUILD_TAG),
                         ('TRUST_CI_RUNNER_IMAGE', runner_tag)):
            found = self.image_digest(tag)
            if found is None:
                raise SetupError(f'the build produced no inspectable image {tag}')
            pins[key] = found
        # The policy check comes first: on a conflict .env keeps its previous pins.
        policy = self.sync_policy_runner(pins['TRUST_CI_RUNNER_IMAGE'], previous=env.get('TRUST_CI_RUNNER_IMAGE'))
        updates = {key: value for key, value in pins.items() if env.get(key) != value}
        if updates:
            write_private(self.path('.env'), render_env(self.path('.env').read_text(encoding='utf-8'), updates))
        return 'built and pinned ' + ', '.join(f'{key}={value}' for key, value in pins.items()) + f'; policy {policy}'

    def sync_policy_runner(self, runner_image: str, *, previous: str | None) -> str:
        path = self.path(POLICY)
        try:
            policy = json.loads(path.read_text(encoding='utf-8'))
            example = json.loads(self.path('config/policy.example.json').read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as exc:
            raise SetupError(f'cannot read {POLICY}: {exc}') from exc
        sandbox = policy.get('sandbox') if isinstance(policy, dict) else None
        if not isinstance(sandbox, dict):
            raise SetupError(f'{POLICY} has no sandbox object')
        current = sandbox.get('image')
        if current == runner_image:
            return 'sandbox.image matches TRUST_CI_RUNNER_IMAGE'
        replaceable = {example.get('sandbox', {}).get('image'), previous} - {None}
        if not isinstance(current, str) or missing(current) or current in replaceable:
            sandbox['image'] = runner_image
            write_public(path, json.dumps(policy, ensure_ascii=False, indent=2) + '\n')
            return 'sandbox.image pinned to TRUST_CI_RUNNER_IMAGE (a new policy epoch)'
        raise SetupError(f'{POLICY} sandbox.image differs from TRUST_CI_RUNNER_IMAGE in .env. Reconcile them by hand; '
                         'a change of sandbox.image changes the policy epoch.')

    def ensure_ci_key(self) -> str:
        private, public = self.path(CI_PRIVATE_KEY), self.path(CI_PUBLIC_KEY)
        if private.exists() or private.is_symlink():
            if not public.is_file():
                raise SetupError(f'{CI_PRIVATE_KEY} exists without {CI_PUBLIC_KEY}; restore the public key from the '
                                 'backup (init never replaces a key)')
            if os.name != 'nt' and private.stat().st_uid == os.getuid() and file_mode(private) & 0o077:
                os.chmod(private, 0o600)
                return f'kept the existing key; tightened {CI_PRIVATE_KEY} to 0600'
            return f'kept the existing key {CI_PRIVATE_KEY}'
        if public.exists():
            raise SetupError(f'{CI_PUBLIC_KEY} exists without its private key; move it aside on purpose, then re-run')
        args, env = self.keygen_command(private, public)
        with private_umask():
            proc = self.step('keygen', args, env=env, timeout=300)
        if not private.is_file():
            raise SetupError(f'keygen did not create {CI_PRIVATE_KEY}')
        os.chmod(private, 0o600)
        try:
            key_id = json.loads((proc.stdout or '').strip().splitlines()[-1]).get('key_id', '?')
        except (IndexError, json.JSONDecodeError, AttributeError):
            key_id = '?'
        return f'generated {CI_PRIVATE_KEY} (0600, worker only) and {CI_PUBLIC_KEY}; key_id {key_id}'

    def keygen_command(self, private: Path, public: Path) -> tuple[list[str], dict[str, str] | None]:
        """`adaptive-trust-ci keygen`: installed tool, else this checkout's module, else the built worker image."""
        installed = self.which('adaptive-trust-ci')
        if installed:
            return [installed, 'keygen', '--private', str(private), '--public', str(public)], None
        probe = self.runner([self.python, '-c', 'import cryptography'], cwd=self.trust, timeout=60)
        if probe.returncode == 0:
            return ([self.python, '-m', 'adaptive_trust_ci.cli', 'keygen', '--private', str(private),
                     '--public', str(public)], {'PYTHONPATH': str(self.trust / 'src')})
        worker = self.env('.env').get('TRUST_CI_WORKER_IMAGE', '')
        if missing(worker) or not IMMUTABLE_IMAGE.fullmatch(worker):
            raise SetupError('cannot run adaptive-trust-ci keygen: no installed tool, no Python cryptography and no '
                             'pinned worker image')
        return (['docker', 'run', '--rm', '--network', 'none', '--user', f'{os.getuid()}:{os.getgid()}',
                 '--volume', f'{private.parent}:/keys', worker, 'keygen', '--private', f'/keys/{private.name}',
                 '--public', f'/keys/{public.name}'], None)

    def start_postgres(self, project: str) -> str:
        self.step('postgres', self.compose(project, 'up', '--detach', '--wait', '--wait-timeout', '300', 'postgres'),
                  timeout=900)
        return f'healthy (volume {project}_trust-ci-postgres)'

    def migrate(self, project: str) -> str:
        proc = self.step('migrate', self.compose(project, 'run', '--rm', 'migrate'), timeout=900)
        return 'schema applied with the migrator role' if 'schema-applied' in (proc.stdout or '') else 'migrations ran'

    def run_harness(self) -> str:
        env = self.env('.env')
        images = {key: env[key] for key in ('TRUST_CI_POSTGRES_IMAGE', 'TRUST_CI_PYTHON_BASE_IMAGE',
                                            'TRUST_CI_TEST_BUILD_TAG') if env.get(key)}
        self.out('[..] live harness: trust-ci/scripts/postgres-integration.sh (disposable database)')
        self.step('harness', ['bash', str(self.path('scripts/postgres-integration.sh'))], cwd=self.trust.parent,
                  env=images, timeout=3600)
        return 'trust-ci/scripts/postgres-integration.sh passed'

    # ----- human steps ----------------------------------------------------------------------

    def github_app_pending(self) -> bool:
        worker = self.env('env/worker.env')
        app_id = worker.get('TRUST_CI_GITHUB_APP_ID', '')
        installation = worker.get('TRUST_CI_GITHUB_INSTALLATION_ID', '')
        key = self.path(APP_PRIVATE_KEY)
        return not (POSITIVE_ID.fullmatch(app_id) and (installation == 'auto' or POSITIVE_ID.fullmatch(installation))
                    and key.is_file())

    def active_trusted_keys(self) -> list[str]:
        try:
            store = json.loads(self.path(TRUST_STORE).read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            return []
        now = datetime.now(timezone.utc)
        active = []
        for key in store.get('keys', []) if isinstance(store, dict) else []:
            if not isinstance(key, dict) or key.get('revoked_at'):
                continue
            key_id = str(key.get('key_id', ''))
            if ed25519_key_id(str(key.get('public_key_pem', ''))) != key_id:
                continue
            try:
                not_after = datetime.fromisoformat(str(key['not_after'])) if key.get('not_after') else None
            except ValueError:
                continue
            if not_after is None or not_after > now:
                active.append(key_id)
        return active

    def public_url(self) -> str | None:
        current = self.env('env/common.env').get('TRUST_CI_PUBLIC_BASE_URL', '')
        return None if missing(current) or current.rstrip('/') == EXAMPLE_PUBLIC_URL else current.rstrip('/')

    def human_steps(self) -> list[dict[str, object]]:
        api_env = self.path('env/api.env')
        url = self.public_url()
        steps: list[dict[str, object]] = []
        if self.github_app_pending():
            lines = []
            if url is None:
                lines += ['Set the public HTTPS address of the API first (the webhook goes there):',
                          '    getzilla trust-ci init --public-url https://<ci-host>']
            lines += [
                'On GitHub: Settings > Developer settings > GitHub Apps > New GitHub App.',
                'Permissions: Checks read and write; Contents read-only; Pull requests read-only. Event: Pull request.',
                f'Webhook URL: {url or "https://<ci-host>"}/webhooks/github',
                'Webhook secret: read it on this host (init never prints it):',
                f"    sed -n 's/^TRUST_CI_WEBHOOK_SECRET=//p' {api_env}",
                'Generate a private key (.pem). Install the App on the private repositories.',
                'Note the App ID and the installation ID ("auto" for an App on several accounts).',
                'On this host:',
                '    getzilla trust-ci github-app --app-id <APP_ID> --installation-id <INSTALLATION_ID|auto> '
                '--private-key <downloaded.pem>',
                'It writes env/worker.env and runtime/github-app-private-key.pem (0600) only. The API never gets them.',
            ]
            steps.append({'number': 1, 'title': 'GitHub App (worker only)', 'lines': lines})
        if not self.active_trusted_keys():
            steps.append({'number': 2, 'title': 'Human approval key, on your own workstation', 'lines': [
                'Not on this host and not in an agent workspace. No agent makes, reads or submits this key.',
                '    adaptive-trust-ci keygen --private ~/.config/adaptive-trust-ci/<you>.pem '
                '--public ~/.config/adaptive-trust-ci/<you>.pub.pem',
                'Keep <you>.pem on the workstation. Note the printed key_id. Copy only <you>.pub.pem to this host.',
                '(Without the installed tool, use the operator venv in trust-ci/README.md, '
                '"Source-checkout operator setup".)',
            ]})
            steps.append({'number': 3, 'title': 'Trust the public key, on this host', 'lines': [
                '    getzilla trust-ci trust-key --public-key <you>.pub.pem --key-id <key_id> --actor <you>',
                'It checks the key_id against the key and writes runtime/trust-store.json (API only).',
            ]})
        return steps

    def checklist(self) -> list[str]:
        steps = self.human_steps()
        if not steps:
            return ['', 'No human steps are pending. Check the host: getzilla trust-ci status']
        lines = ['', 'HUMAN STEPS (only a person can do these; init and agents never do them):']
        for step in steps:
            lines.append(f"{step['number']}. {step['title']}")
            lines += [f'   {line}' for line in step['lines']]  # type: ignore[union-attr]
        lines += ['Then check: getzilla trust-ci status   (exit 0 = ready to start the services; '
                  'see QUICKSTART.md, Start and health)']
        return lines

    def github_app(self, *, app_id: str, installation_id: str, private_key: Path) -> int:
        try:
            worker_path = self.path('env/worker.env')
            if not worker_path.is_file():
                raise SetupError('env/worker.env is missing; run `getzilla trust-ci init` first')
            if not POSITIVE_ID.fullmatch(app_id):
                raise SetupError('--app-id must be a positive integer')
            if installation_id != 'auto' and not POSITIVE_ID.fullmatch(installation_id):
                raise SetupError('--installation-id must be a positive integer or "auto"')
            try:
                data = Path(private_key).read_bytes()
            except OSError as exc:
                raise SetupError(f'cannot read {private_key}: {exc.strerror}') from exc
            text = data.decode('ascii', errors='replace')
            if 'ENCRYPTED' in text or not re.search(r'-----BEGIN (RSA )?PRIVATE KEY-----', text):
                raise SetupError(f'{private_key} is not an unencrypted GitHub App private key '
                                 '(BEGIN RSA PRIVATE KEY or BEGIN PRIVATE KEY)')
            values = read_env(worker_path)
            updates = {}
            for key, wanted in (('TRUST_CI_GITHUB_APP_ID', app_id), ('TRUST_CI_GITHUB_INSTALLATION_ID', installation_id)):
                current = values.get(key, '')
                if missing(current):
                    updates[key] = wanted
                elif current != wanted:
                    raise SetupError(f'env/worker.env already sets a different {key}; edit it by hand to switch Apps')
            target = self.path(APP_PRIVATE_KEY)
            if target.is_dir():
                raise SetupError(f'{APP_PRIVATE_KEY} is a directory. Docker creates one when the worker starts before '
                                 'the key exists. Remove it (sudo rmdir) and run this again.')
            if target.exists():
                try:
                    same = target.read_bytes() == data
                except PermissionError:
                    same = True  # already handed to the worker uid; existence is enough, never replace it
                if not same:
                    raise SetupError(f'a different key is already installed at {APP_PRIVATE_KEY}; move it aside by '
                                     'hand to replace it')
                key_state = 'kept the installed key'
            else:
                write_new_private_bytes(target, data)
                key_state = f'installed {APP_PRIVATE_KEY} (0600)'
            if updates:
                write_private(worker_path, render_env(worker_path.read_text(encoding='utf-8'), updates))
            self.report('ok', 'github-app', f'env/worker.env App ID {app_id}, installation {installation_id}; '
                                            f'{key_state}. env/api.env is unchanged.')
            self.out(f'You can now delete the downloaded copy: shred -u {private_key}')
            return EXIT_READY
        except SetupError as exc:
            self.report('FAIL', 'github-app', str(exc))
            return EXIT_FAILED

    def trust_key(self, *, public_key: Path, actor: str, key_id: str | None = None,
                  scopes: tuple[str, ...] = DEFAULT_SCOPES, days: int = 365) -> int:
        try:
            if not ACTOR.fullmatch(actor):
                raise SetupError('--actor must be one word: letters, digits, ".", "_", "@" or "-"')
            try:
                pem = Path(public_key).read_text(encoding='ascii', errors='replace')
            except OSError as exc:
                raise SetupError(f'cannot read {public_key}: {exc.strerror}') from exc
            if 'PRIVATE KEY' in pem:
                raise SetupError(f'{public_key} is a private key. Never copy the human private key to this host; '
                                 'copy only the .pub.pem file.')
            actual = ed25519_key_id(pem)
            if actual is None:
                raise SetupError(f'{public_key} is not an Ed25519 public key PEM from adaptive-trust-ci keygen')
            if key_id and key_id != actual:
                raise SetupError(f'--key-id {key_id} does not belong to this public key (it is {actual}); '
                                 'check that you copied the right .pub.pem')
            if not 1 <= days <= 3650 or not scopes:
                raise SetupError('--days must be 1..3650 and --scopes must not be empty')
            begin = pem.index('-----BEGIN PUBLIC KEY-----')
            end = pem.index('-----END PUBLIC KEY-----') + len('-----END PUBLIC KEY-----')
            clean = pem[begin:end] + '\n'
            path = self.path(TRUST_STORE)
            try:
                store = json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}
            except json.JSONDecodeError as exc:
                raise SetupError(f'{TRUST_STORE} is not valid JSON: {exc}') from exc
            if not isinstance(store, dict) or not isinstance(store.get('keys', []), list):
                raise SetupError(f'{TRUST_STORE} must be an object with a "keys" list')
            keys =[key for key in store.get('keys', []) if isinstance(key, dict) and not missing(str(key.get('key_id')))]
            for key in keys:
                if key.get('key_id') == actual:
                    if key.get('public_key_pem') != clean:
                        raise SetupError(f'{TRUST_STORE} has key_id {actual} with another public key')
                    self.report('ok', 'trust-key', f'key_id {actual} is already in {TRUST_STORE}')
                    return EXIT_READY
            now = datetime.now(timezone.utc).replace(microsecond=0)
            keys.append({'key_id': actual, 'actor': actor, 'scopes': list(scopes), 'not_before': now.isoformat(),
                         'not_after': (now + timedelta(days=days)).isoformat(), 'revoked_at': None,
                         'public_key_pem': clean})
            store = {**store, 'schema_version': store.get('schema_version', 2), 'keys': keys}
            write_public(path, json.dumps(store, ensure_ascii=False, indent=2) + '\n')
            self.report('ok', 'trust-key', f'key_id {actual} for {actor} ({", ".join(scopes)}) is in {TRUST_STORE}. '
                                           'Restart the API to load it.')
            return EXIT_READY
        except SetupError as exc:
            self.report('FAIL', 'trust-key', str(exc))
            return EXIT_FAILED

    # ----- status ---------------------------------------------------------------------------

    def status(self, *, project: str | None = None, as_json: bool = False) -> int:
        checks: list[dict[str, str]] = []

        def add(name: str, state: str, detail: str) -> None:
            checks.append({'name': name, 'state': state, 'detail': self.redact(detail)})

        try:
            project = self.resolve_project(project)
        except SetupError as exc:
            add('project', 'fail', str(exc))
            project = None
        absent = [rel for _, rel in ENV_FILES if not self.path(rel).is_file()]
        if absent:
            add('env-files', 'todo', f'missing {", ".join(absent)}; run getzilla trust-ci init')
        else:
            loose = [rel for _, rel in ENV_FILES if os.name != 'nt' and file_mode(self.path(rel)) & 0o077]
            holes = [f'{rel}:{key}' for _, rel in ENV_FILES for key, value in self.env(rel).items()
                     if missing(value) and key not in GITHUB_APP_KEYS]
            if loose or holes:
                add('env-files', 'fail', f'not 0600: {", ".join(loose) or "none"}; unfilled: {", ".join(holes) or "none"}')
            else:
                add('env-files', 'ok', 'all present, 0600, no machine placeholders left')
            self.check_secrets(add)
            self.check_key_split(add)
            self.check_images(add)
        self.check_ci_key(add)
        if self.github_app_pending():
            add('github-app', 'todo', 'human step 1: App ID, installation ID and private key for the worker')
        else:
            add('github-app', 'ok', 'env/worker.env and runtime/github-app-private-key.pem')
        active = self.active_trusted_keys()
        add('trust-store', 'ok' if active else 'todo',
            f'active human key(s): {", ".join(active)}' if active else 'human steps 2 and 3: no active human key')
        add('public-url', 'ok' if self.public_url() else 'todo',
            self.public_url() or 'TRUST_CI_PUBLIC_BASE_URL is the example; run init --public-url https://<ci-host>')
        holdout = self.env('.env').get('TRUST_CI_HOLDOUT_SOURCE_PATH', '')
        if holdout and Path(holdout).is_dir():
            add('holdout-source', 'ok', holdout)
        else:
            add('holdout-source', 'todo', f'{holdout or "TRUST_CI_HOLDOUT_SOURCE_PATH"} does not exist; install the '
                                          'reviewed holdout bundle (trust-ci/README.md, external holdout bundle)')
        if project and not absent:
            self.check_postgres(project, add)
        human = self.human_steps()
        failed = any(item['state'] == 'fail' for item in checks)
        pending = any(item['state'] == 'todo' for item in checks)
        code = EXIT_FAILED if failed else EXIT_PENDING if pending else EXIT_READY
        if as_json:
            self.out(json.dumps({'project': project, 'ready': code == EXIT_READY, 'checks': checks,
                                 'human_steps': human}, ensure_ascii=False, indent=2))
            return code
        for item in checks:
            self.out(f"[{item['state']}] {item['name']}: {item['detail']}")
        for line in self.checklist():
            self.out(line)
        return code

    def check_secrets(self, add: Callable[[str, str, str], None]) -> None:
        postgres = self.env('env/postgres.env')
        problems = []
        for password_key, rel, url_key in ROLE_PASSWORDS:
            stored, in_url = postgres.get(password_key), url_password(self.env(rel).get(url_key, ''))
            if missing(stored) or not in_url or stored != in_url:
                problems.append(f'{password_key} vs {rel} {url_key}')
        present = [missing(postgres.get(ADMIN_ENV_KEY))] + [missing(self.env('env/api.env').get(k)) for k in API_SECRETS]
        if any(present):
            problems.append('admin password, webhook secret or read token is missing')
        add('secrets', 'fail' if problems else 'ok',
            '; '.join(problems) if problems else 'role passwords match their database URLs; all machine secrets set')

    def check_key_split(self, add: Callable[[str, str, str], None]) -> None:
        leaks = [f'env/api.env:{key}' for key in API_FORBIDDEN if key in self.env('env/api.env')]
        leaks += [f'env/worker.env:{key}' for key in WORKER_FORBIDDEN if key in self.env('env/worker.env')]
        add('key-split', 'fail' if leaks else 'ok',
            f'forbidden: {", ".join(leaks)}' if leaks else 'API has no GitHub App or CI key; worker has no webhook '
                                                           'secret, read token or trust store')

    def check_images(self, add: Callable[[str, str, str], None]) -> None:
        env = self.env('.env')
        loose = [key for key in IMAGE_KEYS if missing(env.get(key)) or not IMMUTABLE_IMAGE.fullmatch(env.get(key, ''))]
        if loose:
            add('images', 'fail', f'not pinned by digest: {", ".join(loose)}')
            return
        try:
            sandbox = json.loads(self.path(POLICY).read_text(encoding='utf-8')).get('sandbox', {}).get('image')
        except (OSError, json.JSONDecodeError, AttributeError):
            sandbox = None
        if sandbox != env['TRUST_CI_RUNNER_IMAGE']:
            add('images', 'fail', f'{POLICY} sandbox.image is not TRUST_CI_RUNNER_IMAGE')
        else:
            add('images', 'ok', 'all six images pinned; policy sandbox.image = TRUST_CI_RUNNER_IMAGE')

    def check_ci_key(self, add: Callable[[str, str, str], None]) -> None:
        private, public = self.path(CI_PRIVATE_KEY), self.path(CI_PUBLIC_KEY)
        if not private.exists():
            add('ci-key', 'todo', f'{CI_PRIVATE_KEY} is missing; run getzilla trust-ci init')
            return
        if not public.is_file():
            add('ci-key', 'fail', f'{CI_PUBLIC_KEY} is missing')
            return
        if os.name == 'nt':
            add('ci-key', 'ok', CI_PRIVATE_KEY)
            return
        info = private.stat()
        if info.st_mode & 0o077 and not (info.st_uid == WORKER_UID and info.st_mode & 0o007 == 0):
            add('ci-key', 'fail', f'{CI_PRIVATE_KEY} is readable by others (mode {oct(file_mode(private))})')
        elif info.st_uid != WORKER_UID:
            add('ci-key', 'ok', f'{CI_PRIVATE_KEY} 0600. Before the worker starts, give the worker keys to uid '
                                f'{WORKER_UID}: sudo chown {WORKER_UID}:{WORKER_UID} {CI_PRIVATE_KEY} {APP_PRIVATE_KEY}')
        else:
            add('ci-key', 'ok', f'{CI_PRIVATE_KEY} owned by the worker uid {WORKER_UID}')

    def check_postgres(self, project: str, add: Callable[[str, str, str], None]) -> None:
        proc = self.runner(self.compose(project, 'ps', '--all', '--format', 'json', 'postgres'),
                           cwd=self.trust, timeout=60)
        if proc.returncode != 0:
            add('postgres', 'fail', f'`docker compose ps` failed for project {project}')
            return
        rows = parse_compose_ps(proc.stdout or '')
        row = next((item for item in rows if item.get('Service') == 'postgres'), None)
        if row is None:
            add('postgres', 'todo', f'not started in project {project}; run getzilla trust-ci init')
        elif row.get('State') == 'running' and row.get('Health') in {'healthy', ''}:
            add('postgres', 'ok', f'running and healthy in project {project}')
        else:
            add('postgres', 'fail', f"state {row.get('State')}, health {row.get('Health')} in project {project}")


def parse_compose_ps(output: str) -> list[dict[str, str]]:
    """`docker compose ps --format json` prints a JSON array (older) or one object per line (newer)."""
    text = output.strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        items = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        items = []
        for line in text.splitlines():
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return [item for item in items if isinstance(item, dict)]
