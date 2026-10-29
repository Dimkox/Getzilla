"""Provider identity is offline and must never upgrade unknown hosts to GitHub."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.git_platforms import inspect_repository, parse_remote, platform_catalog


class RemoteIdentityTests(unittest.TestCase):
    def test_entire_native_and_mirror_keep_transport_and_authority_separate(self):
        for forge, authority, mode in [('et', 'entire', 'native'), ('gh', 'github', 'mirror')]:
            url = f'entire://us-east-1.entire.io/{forge}/team/project'
            identity = parse_remote(url)
            self.assertIsNotNone(identity)
            self.assertEqual(identity.provider, 'entire')
            self.assertEqual(identity.mode, mode)
            self.assertEqual(identity.authoritative_forge, authority)
            self.assertEqual(identity.clone_url, url)
            self.assertEqual(identity.transport_host, 'us-east-1.entire.io')
            self.assertEqual(identity.repository, 'team/project')
            self.assertEqual(identity.resource, url)

    def test_github_transports_have_one_identity(self):
        for url in ['https://github.com/Owner/Repo.git', 'git@github.com:Owner/Repo.git',
                    'ssh://git@ssh.github.com:443/Owner/Repo.git']:
            identity = parse_remote(url)
            self.assertEqual((identity.provider, identity.repository), ('github', 'Owner/Repo'))
            self.assertEqual(identity.resource, 'https://github.com/Owner/Repo')

    def test_dot_leading_repository_and_entire_git_suffix_are_supported(self):
        self.assertEqual(parse_remote('https://github.com/example/.github.git').repository, 'example/.github')
        for forge in ('et', 'gh'):
            url = f'entire://aws-us-east-2.entire.io/{forge}/team/repo.git'
            identity = parse_remote(url)
            self.assertEqual(identity.repository, 'team/repo')
            self.assertEqual(identity.clone_url, url)
            self.assertEqual(identity.resource, url.removesuffix('.git'))

    def test_never_accepts_secrets_ambiguous_paths_or_lookalike_entire_hosts(self):
        for url in ['', 'entire://evil.test/et/a/b', 'entire://x.entire.io.evil.test/et/a/b',
                    'entire://token@x.entire.io/et/a/b', 'entire://x.entire.io:443/et/a/b',
                    'entire://x.entire.io/et/a/b?token=secret', 'entire://x.entire.io/et/a/..',
                    'entire://x.entire.io/et/a/%2e%2e', 'entire://x.entire.io/et/a/b#ref',
                    'entire://x.entire.io/et/a/b/extra', 'entire://x.entire.io/other/a/b',
                    'https://user:secret@github.com/a/b', 'https://github.com/a/%2fb',
                    'https://github.com/a/b\nsecret', 'ssh://-oProxyCommand=x@github.com/a/b']:
            with self.subTest(url=url):
                self.assertIsNone(parse_remote(url))

    def test_candidates_do_not_inherit_github_capabilities(self):
        for url, provider in [('https://gitlab.com/group/sub/repo.git', 'gitlab'),
                              ('git@codeberg.org:owner/repo.git', 'codeberg'),
                              ('https://github.com.evil.test/owner/repo', 'generic'),
                              ('https://company.ghe.com/owner/repo', 'github-enterprise'),
                              ('https://dev.azure.com/org/proj/_git/repo', 'azure-repos')]:
            self.assertEqual(parse_remote(url).provider, provider)


class CatalogTests(unittest.TestCase):
    def test_current_catalog_and_evidence_are_explicit(self):
        catalog = platform_catalog()
        entries = {entry['id']: entry for entry in catalog['platforms']}
        self.assertTrue({'local', 'github', 'github-enterprise', 'entire-native', 'entire-mirror',
                         'cursor-origin', 'gitlab', 'bitbucket-cloud', 'bitbucket-data-center',
                         'azure-repos', 'gitea', 'forgejo', 'codeberg', 'codecommit', 'gitee',
                         'gitcode', 'gitflic', 'gitverse', 'sourcehut', 'generic'} <= entries.keys())
        self.assertNotIn('bitbucket-server', entries)
        for entry in entries.values():
            self.assertFalse(entry['hosted_e2e_verified'])
            self.assertTrue(entry['evidence'])
            self.assertTrue(entry['limitations'])
            self.assertIn('merge', entry['capabilities'])
        self.assertEqual(entries['entire-native']['capabilities']['merge'], 'unsupported')
        self.assertEqual(entries['gitlab']['capabilities']['checks'], 'unsupported')
        self.assertEqual(entries['entire-mirror']['contract_version'], '0.12.2')
        self.assertIsNone(entries['entire-mirror']['tested_version'])

    def test_inspection_works_without_network_or_optional_provider(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            self.assertEqual(inspect_repository(root)['platform'], 'local')
            subprocess.run(['git', '-C', str(root), 'remote', 'add', 'origin',
                            'entire://us-east-1.entire.io/et/team/repo'], check=True)
            result = inspect_repository(root)
            self.assertEqual(result['platform'], 'entire-native')
            self.assertFalse(result['hosted_e2e_verified'])

    def test_catalog_cli_json(self):
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/getzilla_git.py'), 'catalog', '--json'],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), platform_catalog())


if __name__ == '__main__':
    unittest.main()
