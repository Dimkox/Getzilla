"""Pinned Entire CLI wire contract with explicit authentication and cell boundaries."""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

from getzilla.git_platforms import RemoteIdentity, entire_host
from . import SUPPORTED_CLI_VERSION
from .process import ProcessResult, bounded_run

ULID = re.compile(r'[0-9A-HJKMNP-TV-Z]{26}\Z')
SHA = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')


class EntireError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def reject_git_overrides(environment: dict[str, str] | None = None) -> None:
    """Authority and transport must observe the same root, index, refs and config."""
    for values in (os.environ, environment or {}):
        if any(key.startswith('GIT_') and key not in {'GIT_TERMINAL_PROMPT', 'GIT_PAGER'} for key in values):
            raise EntireError('git_environment', 'unset inherited Git repository/configuration overrides before using the Entire adapter')


def safe_origin(value: object) -> str:
    if not isinstance(value, str) or len(value) > 512 or any(c in value for c in '\\%?#'):
        raise EntireError('untrusted_origin', 'Entire API origin is outside the supported production boundary')
    try:
        url = urlsplit(value)
        host = url.hostname or ''
        valid = (url.scheme == 'https' and (host == 'entire.io' or entire_host(host))
                 and url.username is None and url.password is None and url.port in (None, 443)
                 and url.path in ('', '/') and not url.query and not url.fragment
                 and not any(ord(c) <= 32 or ord(c) == 127 for c in value))
    except ValueError:
        valid = False
    if not valid:
        raise EntireError('untrusted_origin', 'Entire API origin is outside the supported production boundary')
    return f'https://{host}'


def decode_json(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('non-finite JSON')
    try:
        result = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
        if not isinstance(result, dict):
            raise ValueError('object required')
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise EntireError('invalid_json', 'Entire returned malformed or unsupported JSON') from exc
    return result


def read_metadata(path: Path, limit: int = 256 * 1024) -> dict:
    """Read bounded non-secret configuration metadata, never a token/keychain file."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
                raise OSError('unsafe metadata')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                content = stream.read(limit + 1)
            if len(content) > limit:
                raise OSError('oversized metadata')
        finally:
            os.close(fd)
    except OSError as exc:
        raise EntireError('configuration', 'Entire metadata is missing, linked, unsafe or too large; configure Entire explicitly') from exc
    return decode_json(content)


@dataclass(frozen=True)
class Repository:
    identity: RemoteIdentity
    repo_id: str
    api_url: str
    visibility: str
    can_push: bool | None

    @property
    def selector(self) -> str:
        return f'{self.identity.forge}/{self.identity.repository}'

    @property
    def project(self) -> str:
        return self.selector.rsplit('/', 1)[0]


class EntireClient:
    def __init__(self, root: Path, *, context: str, config_dir: Path | None = None,
                 runner: Callable = bounded_run, which: Callable = shutil.which,
                 environment: dict[str, str] | None = None, timeout: float = 30):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@:-]{0,254}', context):
            raise EntireError('context', 'an explicit valid Entire context name is required')
        self.root, self.context, self.runner, self.which = root, context, runner, which
        self.environment = dict(os.environ if environment is None else environment)
        self.config_dir = config_dir
        self.timeout = timeout
        self.core_url = ''

    def environment_for(self, api_url: str | None = None) -> dict[str, str]:
        reject_git_overrides(self.environment)
        # ENTIRE_TOKEN overrides contexts and chooses its audience before auth status.
        # Support saved contexts only; never inspect or forward this secret override.
        if 'ENTIRE_TOKEN' in self.environment:
            raise EntireError('env_token_unsupported', 'unset ENTIRE_TOKEN and select an explicitly configured Entire context')
        configured = self.config_dir or Path(self.environment.get('ENTIRE_CONFIG_DIR') or str(Path.home() / '.config/entire'))
        if not configured.is_absolute():
            raise EntireError('configuration', 'ENTIRE_CONFIG_DIR must be an absolute path')
        metadata = read_metadata(configured / 'contexts.json')
        contexts = metadata.get('contexts')
        if not isinstance(contexts, list):
            raise EntireError('configuration', 'Entire contexts metadata has an unsupported schema')
        matches = [item for item in contexts if isinstance(item, dict) and item.get('name') == self.context]
        if len(matches) != 1:
            raise EntireError('context', 'the selected Entire context is missing or duplicated; configure it explicitly')
        selected = matches[0]
        self.core_url = safe_origin(selected.get('core_url'))
        audiences = selected.get('jurisdiction_audiences', [])
        if not isinstance(audiences, list) or len(audiences) > 256 or any(not isinstance(a, str) or len(a) > 2048 for a in audiences):
            raise EntireError('configuration', 'Entire jurisdiction metadata has an unsupported schema')
        # Routing overrides must not change the credential audience between commands.
        env = {key: value for key, value in self.environment.items()
               if not key.startswith(('ENTIRE_', 'GIT_')) and key not in
               {'GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'}}
        env.update(ENTIRE_CONTEXT=self.context, ENTIRE_CONFIG_DIR=str(configured),
                   ENTIRE_TELEMETRY_OPTOUT='1', ENTIRE_NO_AUTO_UPDATE='1',
                   GIT_TERMINAL_PROMPT='0')
        if api_url is not None:
            env['ENTIRE_API_BASE_URL'] = safe_origin(api_url)
        return env

    def executable(self, name: str) -> str:
        path = self.which(name)
        if not path:
            raise EntireError('missing_tool', f'{name} is required; install it explicitly before using the Entire adapter')
        return path

    def run(self, argv: list[str], *, api_url: str | None = None, input_data: bytes = b'',
            allowed_codes: tuple[int, ...] = (0,)) -> ProcessResult:
        result = self.runner(argv, cwd=self.root, env=self.environment_for(api_url), input_data=input_data,
                             timeout=self.timeout, max_output=2 * 1024 * 1024)
        if result.status != 'completed':
            raise EntireError(result.status, f'Entire operation stopped: {result.status}; no automatic retry')
        if result.returncode not in allowed_codes:
            # stdout/stderr may contain tokens, response bodies or private source. Do not echo them.
            raise EntireError('provider_failed', 'Entire operation failed; check authentication, permissions and service status; no automatic retry')
        return result

    def command_json(self, args: list[str], *, api_url: str | None = None, input_data: bytes = b'') -> dict:
        result = self.run([self.executable('entire'), '--context', self.context, *args],
                          api_url=api_url, input_data=input_data)
        return decode_json(result.stdout)

    def prepare(self) -> None:
        self.environment_for()  # Validate audiences *before* status can refresh or send a token.
        for tool in ('git', 'git-remote-entire'):
            self.executable(tool)
        version = self.run([self.executable('entire'), 'version']).stdout.splitlines()
        if not version or version[0] != f'Entire CLI {SUPPORTED_CLI_VERSION}'.encode():
            raise EntireError('unsupported_version', f'this experimental adapter requires Entire CLI {SUPPORTED_CLI_VERSION}')
        auth = self.command_json(['auth', 'status', '--json'])
        if (auth.get('logged_in') is not True or auth.get('login_revoked') or auth.get('error')
                or auth.get('sessions_error') or auth.get('context') != self.context
                or not isinstance(auth.get('server'), str)
                or safe_origin('https://' + auth['server']) != self.core_url):
            raise EntireError('authentication', 'Entire authentication is missing, revoked, mismatched or unavailable; authenticate explicitly')

    def discover(self, identity: RemoteIdentity, *, qualified: bool = True) -> Repository:
        if identity is None or identity.provider != 'entire':
            raise EntireError('unsupported_remote', 'select a validated entire:// native or GitHub-mirror remote')
        self.prepare()
        selector = identity.clone_url if qualified else f'{identity.forge}/{identity.repository}'
        args = ['repo', 'view', selector, '--json']
        if identity.mode == 'native':
            args.append('--authoritative')
        data = self.command_json(args)
        if data.get('repo') != f'/{identity.forge}/{identity.repository}' or not ULID.fullmatch(str(data.get('repoId', ''))):
            raise EntireError('repository_mismatch', 'Entire returned a different or unsupported repository identity')
        api_url = safe_origin(data.get('apiUrl'))
        if data.get('syncBlock') or data.get('syncStatus') == 'unavailable':
            raise EntireError('mirror_unavailable', 'Entire mirror synchronization is blocked or unavailable')
        visibility = data.get('visibility')
        if visibility not in {'public', 'private'}:
            private = data.get('private')
            visibility = ('private' if private else 'public') if isinstance(private, bool) else 'unknown'
        capabilities = data.get('capabilities', {})
        can_push = capabilities.get('canPush') if isinstance(capabilities, dict) else None
        return Repository(identity, data['repoId'], api_url, visibility,
                          can_push if isinstance(can_push, bool) else None)

    def change_detail(self, repository: Repository, number: int) -> dict:
        if type(number) is not int or not 1 <= number <= 2**31 - 1:
            raise EntireError('change_number', 'a positive repository change number is required')
        return self.command_json(['api', '--to', 'cell', '--method', 'GET',
                                  f'/api/v1/repos/{repository.repo_id}/trails/{number}'], api_url=repository.api_url)
