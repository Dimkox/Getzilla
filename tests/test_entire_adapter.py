"""Official v0.12.2 wire shapes; these offline fixtures are not live-host certification."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))
sys.path.insert(0, str(ROOT / '.getzilla/integrations'))
from getzilla.git_platforms import parse_remote
from getzilla_entire.client import EntireClient, EntireError
from getzilla_entire.process import ProcessResult

REPO_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAB'
TRAIL_ID = '01ARZ3NDEKTSV4RRFFQ69G5FAW'
HEAD = 'a' * 40
URL = 'entire://aws-us-east-2.entire.io/et/team/repo'
MIRROR = 'entire://aws-us-east-2.entire.io/gh/team/repo'
API = 'https://aws-eu-central-1.api.entire.io'


def response(value):
    return ProcessResult(0, json.dumps(value).encode())


class FixtureRunner:
    def __init__(self):
        self.calls = []
        self.auth = {'logged_in': True, 'server': 'entire.io', 'context': 'work'}
        self.version = b'Entire CLI 0.12.2\nGo version: fixture\nOS/Arch: fixture\n'
        self.repo = {'repo': '/et/team/repo', 'repoId': REPO_ID, 'apiUrl': API,
                     'visibility': 'private', 'capabilities': {'canPull': True, 'canPush': True},
                     'status': 'ready', 'placements': []}
        self.extra = {}

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        args = list(argv)[1:]
        if args == ['version']:
            return ProcessResult(0, self.version)
        if args[:2] == ['--context', 'work']:
            args = args[2:]
        if args == ['auth', 'status', '--json']:
            return response(self.auth)
        if args[:2] == ['repo', 'view']:
            return response(self.repo)
        key = tuple(args)
        if key in self.extra:
            return self.extra[key]
        raise AssertionError(f'unexpected process: {args}')


class ClientTests(unittest.TestCase):
    def setUp(self):
        environment = mock.patch.dict(os.environ, {key: value for key, value in os.environ.items()
                                      if not key.startswith('GIT_')}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'user-config'
        self.config.mkdir()
        self.contexts = {'current_context': 'work', 'contexts': [
            {'name': 'work', 'core_url': 'https://entire.io', 'handle': 'user', 'keychain_service': 'fixture'}]}
        self.write_contexts()
        self.runner = FixtureRunner()
        self.client = EntireClient(self.root, context='work', config_dir=self.config,
                                   runner=self.runner, which=lambda name: '/usr/bin/' + name,
                                   environment={'PATH': '/usr/bin'})

    def write_contexts(self):
        (self.config / 'contexts.json').write_text(json.dumps(self.contexts), encoding='utf-8')

    def test_native_repo_uses_authoritative_and_preserves_cell_routing(self):
        repo = self.client.discover(parse_remote(URL))
        self.assertEqual((repo.repo_id, repo.api_url, repo.visibility), (REPO_ID, API, 'private'))
        call = self.runner.calls[-1][0]
        self.assertEqual(call[-2:], ['--json', '--authoritative'])
        self.assertIn(URL, call)

    def test_mirror_does_not_inherit_native_permissions(self):
        self.runner.repo = {'repo': '/gh/team/repo', 'repoId': REPO_ID, 'apiUrl': API, 'private': True}
        repo = self.client.discover(parse_remote(MIRROR))
        self.assertIsNone(repo.can_push)
        self.assertNotIn('--authoritative', self.runner.calls[-1][0])

    def test_decorated_clone_url_matches_canonical_native_and_mirror_response(self):
        for url, forge in [(URL, 'et'), (MIRROR, 'gh')]:
            self.runner.repo['repo'] = f'/{forge}/team/repo'
            repo = self.client.discover(parse_remote(url + '.git'))
            self.assertEqual(repo.identity.repository, 'team/repo')
            self.assertIn(url + '.git', self.runner.calls[-1][0])

    def test_exit_zero_logged_out_revoked_or_error_is_refused(self):
        for auth in ({'logged_in': False}, {'logged_in': True, 'login_revoked': True},
                     {'logged_in': True, 'error': 'secret detail'}, {'logged_in': 'true'}, {}):
            self.runner.auth = auth
            with self.subTest(auth=auth), self.assertRaises(EntireError) as error:
                self.client.discover(parse_remote(URL))
            self.assertNotIn('secret detail', str(error.exception))

    def test_version_mismatch_and_missing_helper_fail_before_network(self):
        self.runner.version = b'Entire CLI 0.13.0\n'
        with self.assertRaisesRegex(EntireError, '0.12.2'):
            self.client.discover(parse_remote(URL))
        self.assertEqual(len(self.runner.calls), 1)
        self.client.which = lambda name: None if name == 'git-remote-entire' else '/usr/bin/' + name
        with self.assertRaisesRegex(EntireError, 'git-remote-entire'):
            self.client.discover(parse_remote(URL))

    def test_untrusted_auth_origin_is_rejected_before_auth_status(self):
        for host in ['https://evil.test', 'https://entire.io.evil.test', 'http://entire.io',
                     'https://user:secret@entire.io', 'https://entire.io/path']:
            self.contexts['contexts'][0]['core_url'] = host
            self.write_contexts()
            self.runner.calls.clear()
            with self.subTest(host=host), self.assertRaises(EntireError):
                self.client.discover(parse_remote(URL))
            self.assertFalse(any('auth' in call[0] for call in self.runner.calls))

    def test_env_token_is_rejected_without_inspecting_or_sending_it(self):
        self.client.environment['ENTIRE_TOKEN'] = 'do-not-send'
        with self.assertRaisesRegex(EntireError, 'ENTIRE_TOKEN'):
            self.client.discover(parse_remote(URL))
        self.assertFalse(self.runner.calls)

    def test_foreign_api_and_wrong_repository_fail_closed(self):
        for change in [{'apiUrl': 'https://evil.test'}, {'apiUrl': 'https://entire.io.evil.test'},
                       {'repoId': 'not-a-repo-id'}, {'repo': '/et/other/repo'}, {'apiUrl': None}]:
            original = self.runner.repo.copy()
            self.runner.repo.update(change)
            with self.subTest(change=change), self.assertRaises(EntireError):
                self.client.discover(parse_remote(URL))
            self.runner.repo = original

    def test_context_schema_and_child_environment_match_upstream(self):
        self.contexts['contexts'][0]['jurisdiction_audiences'] = ['legacy-eu-audience']
        self.write_contexts()
        self.client.environment.update(GITHUB_TOKEN='do-not-forward', GH_TOKEN='also-private',
                                       ENTIRE_API_BASE_URL='https://evil.test')
        self.client.discover(parse_remote(URL))
        environment = self.runner.calls[-1][1]['env']
        self.assertNotIn('GH_TOKEN', environment)
        self.assertNotIn('GITHUB_TOKEN', environment)
        self.assertNotIn('ENTIRE_API_BASE_URL', environment)
        self.assertNotIn('GIT_CONFIG_COUNT', environment)
        self.assertEqual(environment['ENTIRE_TELEMETRY_OPTOUT'], '1')
        self.assertEqual(environment['ENTIRE_NO_AUTO_UPDATE'], '1')
        self.assertEqual(environment['ENTIRE_CONTEXT'], 'work')

    def test_git_environment_cannot_split_transport_and_grant_repository(self):
        for variable in ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_GLOBAL']:
            with self.subTest(variable=variable), mock.patch.dict(os.environ, {variable: 'foreign-checkout'}):
                with self.assertRaises(EntireError) as error:
                    self.client.environment_for()
                self.assertEqual(error.exception.code, 'git_environment')

    def test_account_qualified_context_and_empty_config_override(self):
        name = 'alice@us.auth.entire.io'
        self.contexts['contexts'][0]['name'] = name
        self.write_contexts()
        client = EntireClient(self.root, context=name, config_dir=self.config, environment={})
        self.assertEqual(client.environment_for()['ENTIRE_CONTEXT'], name)
        fallback = self.root / '.config/entire'
        fallback.mkdir(parents=True)
        (fallback / 'contexts.json').write_text(json.dumps(self.contexts), encoding='utf-8')
        client.config_dir = None
        client.environment['ENTIRE_CONFIG_DIR'] = ''
        with mock.patch.object(Path, 'home', return_value=self.root):
            self.assertEqual(client.environment_for()['ENTIRE_CONFIG_DIR'], str(fallback))

    def test_detail_uses_discovered_cell_not_clone_hostname(self):
        repo = self.client.discover(parse_remote(URL))
        args = ('api', '--to', 'cell', '--method', 'GET', f'/api/v1/repos/{REPO_ID}/trails/7')
        self.runner.extra[args] = response({'number': 7})
        self.assertEqual(self.client.change_detail(repo, 7), {'number': 7})
        self.assertEqual(self.runner.calls[-1][1]['env']['ENTIRE_API_BASE_URL'], API)

    def test_authentication_server_and_context_cannot_drift(self):
        for change in [{'server': 'evil.test'}, {'server': 'other.entire.io'}, {'context': 'other'}]:
            original = self.runner.auth.copy()
            self.runner.auth.update(change)
            with self.subTest(change=change), self.assertRaises(EntireError):
                self.client.discover(parse_remote(URL))
            self.runner.auth = original

    def test_json_duplicate_keys_and_invalid_utf8_are_rejected(self):
        for payload in [b'{"logged_in":false,"logged_in":true}', b'\xff', b'[]', b'{"logged_in":NaN}']:
            self.runner.extra[('probe',)] = ProcessResult(0, payload)
            with self.subTest(payload=payload), self.assertRaises(EntireError):
                self.client.command_json(['probe'])


if __name__ == '__main__':
    unittest.main()
