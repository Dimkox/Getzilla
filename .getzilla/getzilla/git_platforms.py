"""Offline Git provider identities and an evidence-qualified capability catalog.

Identification never selects a CI gate or performs remote work. Self-hosted software
cannot be inferred from an arbitrary hostname; those remotes remain generic.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

CATALOG_DATE = '2026-10-29'
CAPABILITIES = ('local_input', 'clone', 'fetch', 'push', 'visibility', 'review_requests',
                'checks', 'webhooks', 'merge', 'lfs', 'submodules', 'session_evidence')
_SEGMENT = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}\Z')
_HOST = re.compile(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z')
_HOSTS = {
    'github.com': 'github', 'ssh.github.com': 'github', 'gitlab.com': 'gitlab',
    'bitbucket.org': 'bitbucket-cloud', 'altssh.bitbucket.org': 'bitbucket-cloud',
    'dev.azure.com': 'azure-repos', 'ssh.dev.azure.com': 'azure-repos',
    'codeberg.org': 'codeberg', 'gitee.com': 'gitee', 'gitcode.com': 'gitcode',
    'atomgit.com': 'gitcode', 'gitflic.ru': 'gitflic', 'gitverse.ru': 'gitverse',
    'git.sr.ht': 'sourcehut',
}


def entire_host(host: str) -> bool:
    """Production Entire DNS only; a caller cannot enroll a new credential audience."""
    return bool(_HOST.fullmatch(host) and host.endswith('.entire.io')
                and all(label and not label.startswith('-') and not label.endswith('-')
                        for label in host.split('.')))


@dataclass(frozen=True)
class RemoteIdentity:
    provider: str
    mode: str
    transport_host: str
    repository: str
    authoritative_forge: str
    clone_url: str
    resource: str

    @property
    def platform(self) -> str:
        return f'entire-{self.mode}' if self.provider == 'entire' else self.provider

    @property
    def forge(self) -> str:
        return 'et' if self.mode == 'native' else 'gh'


def parse_remote(value: str) -> RemoteIdentity | None:
    """Return a credential-free, unambiguous identity; never echo rejected URLs."""
    if not isinstance(value, str) or len(value) > 4096:
        return None
    value = value.strip()
    if not value or any(ord(c) < 33 or ord(c) == 127 for c in value) or any(c in value for c in '%\\?#'):
        return None
    # Git's SCP form is not an RFC URL. Only a literal SSH user is accepted.
    parsed_value = value
    if '://' not in value:
        scp = re.fullmatch(r'(?:git@)?([A-Za-z0-9.-]+):([A-Za-z0-9_~./-]+)', value)
        if not scp:
            return None
        parsed_value = f'ssh://git@{scp[1]}/{scp[2]}'
    try:
        parsed = urlsplit(parsed_value)
        host = (parsed.hostname or '').lower()
        port = parsed.port
    except ValueError:
        return None
    if (not _HOST.fullmatch(host) or '..' in host or host.endswith('.') or parsed.password is not None
            or (parsed.username is not None and not (parsed.scheme == 'ssh' and parsed.username == 'git'))):
        return None
    if parsed.scheme not in {'https', 'http', 'ssh', 'git', 'entire'}:
        return None
    parts = parsed.path.strip('/').split('/')
    # SourceHut's ~owner is a valid ordinary Git path, but never an Entire identity.
    if any(not _SEGMENT.fullmatch(p.removeprefix('~')) or p in {'.', '..'} for p in parts):
        return None
    if parsed.scheme == 'entire':
        if (not entire_host(host) or port is not None or len(parts) != 3
                or parts[0] not in {'et', 'gh'} or parsed.path != '/' + '/'.join(parts)
                or any(p.startswith('~') for p in parts)):
            return None
        mode = 'native' if parts[0] == 'et' else 'mirror'
        resource = f'entire://{host}/' + '/'.join(parts)
        return RemoteIdentity('entire', mode, host, '/'.join(parts[1:]),
                              'entire' if mode == 'native' else 'github', value, resource)
    if len(parts) < 2:
        return None
    parts[-1] = parts[-1].removesuffix('.git')
    if not parts[-1] or parts[-1] in {'.', '..'}:
        return None
    provider = _HOSTS.get(host, 'generic')
    if host.endswith('.ghe.com'):
        provider = 'github-enterprise'
    elif host.endswith('.visualstudio.com'):
        provider = 'azure-repos'
    elif re.fullmatch(r'git-codecommit\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?', host):
        provider = 'codecommit'
    if provider == 'github' and (len(parts) != 2 or (port is not None and not (host == 'ssh.github.com' and port == 443))):
        return None
    repository = '/'.join(parts)
    resource = f'https://github.com/{repository}' if provider == 'github' else f'{parsed.scheme}://{host}' + (f':{port}' if port else '') + f'/{repository}'
    return RemoteIdentity(provider, 'hosted', host, repository, provider, value, resource)


def platform_catalog() -> dict:
    """One source for the CLI matrix. Experimental means offline-tested, not hosted E2E."""
    definitions = (
        ('local', 'Local Git / source-folder adoption', 'implemented', 'docs/project-ingestion.md',
         'Remote authentication and fetch are separate; adoption is not a Git host.'),
        ('github', 'GitHub.com', 'implemented', '.getzilla/getzilla/ci_gate.py',
         'Public Actions and private Trust CI require different setup; pilot PR publication is scoped.'),
        ('github-enterprise', 'GitHub Enterprise Server / Cloud on ghe.com', 'candidate', 'https://docs.github.com/en/enterprise-cloud@latest/admin',
         'No custom-host API, authentication or Trust CI adapter.'),
        ('entire-native', 'Entire native repositories', 'experimental', 'https://github.com/entireio/cli/tree/v0.12.2',
         'Optional extra:entire; trusted CI provenance and automated merge are unsupported; no hosted E2E.'),
        ('entire-mirror', 'Entire GitHub mirrors', 'experimental', 'https://docs.entire.com/guides/repositories/mirrors',
         'Transport is Entire; GitHub authority is separate. LFS and automatic upstream/merge claims are unsupported.'),
        ('cursor-origin', 'Cursor Origin (native / mirrored)', 'candidate', 'https://cursor.com/docs/origin',
         'Vendor early beta; native and mirrored APIs require separate adapters.'),
        ('gitlab', 'GitLab.com / Self-Managed / Dedicated', 'candidate', 'https://docs.gitlab.com/api/',
         'Local checkout only; no MR, CI or configured-instance adapter.'),
        ('bitbucket-cloud', 'Bitbucket Cloud', 'candidate', 'https://developer.atlassian.com/cloud/bitbucket/rest/',
         'Cloud API is separate from Data Center; no PR/pipeline adapter.'),
        ('bitbucket-data-center', 'Bitbucket Data Center', 'candidate', 'https://www.atlassian.com/licensing/data-center-end-of-life',
         'Bitbucket Server ended support 2024-02-15; Data Center is a separate target and excluded from the general 2029 EOL.'),
        ('azure-repos', 'Azure Repos Git (Services / Server)', 'candidate', 'https://learn.microsoft.com/en-us/azure/devops/repos/git/',
         'No PR/build-policy adapter; TFVC is outside this Git catalog.'),
        ('gitea', 'Gitea', 'candidate', 'https://docs.gitea.com/', 'Instance/version-specific API validation is required.'),
        ('forgejo', 'Forgejo', 'candidate', 'https://forgejo.org/docs/latest/', 'Gitea API equivalence is not assumed.'),
        ('codeberg', 'Codeberg', 'candidate', 'https://docs.codeberg.org/getting-started/what-is-codeberg/', 'Hosted Forgejo needs independent policy and permission validation.'),
        ('codecommit', 'AWS CodeCommit', 'candidate', 'https://docs.aws.amazon.com/codecommit/latest/userguide/history.html', 'Reopened to new customers in November 2025; AWS auth and region support are pending.'),
        ('gitee', 'Gitee', 'candidate', 'https://gitee.com/', 'No provider API, PR or status adapter.'),
        ('gitcode', 'GitCode / AtomGit', 'candidate', 'https://docs.gitcode.com/en/docs/help/home/aboutus/', 'Consolidated names are aliases, not two implemented integrations; endpoint/account mapping needs validation.'),
        ('gitflic', 'GitFlic (cloud / self-hosted)', 'candidate', 'https://dev.astra.ru/products/gitflic', 'Endpoint, version and PR/CI mapping need validation.'),
        ('gitverse', 'GitVerse', 'candidate', 'https://gitverse.ru/home/', 'No API/auth/review adapter.'),
        ('sourcehut', 'SourceHut Git', 'candidate', 'https://sourcehut.org/', 'Email/patch review needs a separate mapping; Mercurial is outside this catalog.'),
        ('generic', 'Other SSH/HTTPS Git servers', 'local_checkout_only', 'docs/project-ingestion.md', 'Generic Git transport does not imply PRs, webhooks, CI or merge policy.'),
    )
    platforms = []
    for key, name, status, evidence, limitation in definitions:
        capabilities = dict.fromkeys(CAPABILITIES, 'unsupported')
        capabilities['local_input'] = 'implemented' if key == 'local' else 'local_checkout_only'
        if key == 'github':
            capabilities.update(visibility='implemented', checks='implemented')
        if key.startswith('entire-'):
            capabilities.update(clone='experimental', fetch='experimental', push='experimental',
                                visibility='experimental', review_requests='experimental', checks='experimental')
        platforms.append({'id': key, 'name': name, 'status': status, 'capabilities': capabilities,
                          'contract_version': '0.12.2' if key.startswith('entire-') else None,
                          'tested_version': None, 'api_audit_date': CATALOG_DATE,
                          'os_scope': ('POSIX only; Linux offline tests; macOS unverified; Windows remote operations unsupported'
                                       if key.startswith('entire-') else 'local Python tests; hosted OS matrix unverified'),
                          'hosted_e2e_verified': False, 'evidence': [evidence, 'tests/test_git_platforms.py'] +
                          (['tests/test_entire_adapter.py', 'tests/test_entire_authority.py',
                            'tests/test_entire_process.py', 'tests/test_entire_install.py'] if key.startswith('entire-') else []),
                          'limitations': [limitation]})
    return {'schema_version': 1, 'updated_at': CATALOG_DATE, 'platforms': platforms}


def inspect_repository(root: Path, remote: str = 'origin') -> dict:
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', remote):
        raise ValueError('invalid remote name')
    def git(*args):
        return subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                              text=True, encoding='utf-8', errors='replace', timeout=5, check=False)
    inside = git('rev-parse', '--is-inside-work-tree')
    if inside.returncode or inside.stdout.strip() != 'true':
        raise ValueError('path must be an existing Git worktree; use getzilla adopt for a source folder')
    result = git('remote', 'get-url', remote)
    identity = parse_remote(result.stdout) if result.returncode == 0 else None
    platform = identity.platform if identity else ('local' if result.returncode else 'unknown')
    return {'schema_version': 1, 'platform': platform, 'remote': remote,
            'identity': asdict(identity) if identity else None, 'hosted_e2e_verified': False,
            'diagnostic': 'remote URL is unsupported or contains credentials' if platform == 'unknown' else None}
