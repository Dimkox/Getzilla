"""Synthetic signed CI and SDK records; no hosted Entire acceptance is claimed."""
from __future__ import annotations
import base64
import copy
from dataclasses import replace
import json
import unittest
from unittest import mock

from tests import test_entire_authority as support
from getzilla_entire.authority import EntireCheckAuthority, EntireCheckPublisher, canonical
from getzilla_entire.client import EntireError, Repository
from getzilla.git_platforms import parse_remote
from getzilla_entire.process import ProcessResult
from tests.test_entire_adapter import API, HEAD, MIRROR, REPO_ID, TRAIL_ID, URL

BASE, TREE, MERGED = 'b' * 40, 'c' * 40, 'd' * 40
BRANCH = 'getzilla/task'


class QualifiedMergeTests(unittest.TestCase):
    trail = support.WriteGuardTests.trail

    def setUp(self):
        support.WriteGuardTests.setUp(self)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self.key = Ed25519PrivateKey.generate()
        self.authority = EntireCheckAuthority('getzilla-ci',
            self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            '1' * 64, '2' * 64, ('verify',), clock=lambda: 100)
        self.adapter.authority = self.authority
        self.merged = False
        self.adapter.remote_head.side_effect = lambda repo, branch: HEAD if branch == BRANCH else MERGED if self.merged else BASE
        self.adapter.git = mock.Mock(return_value=ProcessResult(0, TREE.encode()))
        self.detail = {'id': self.trail()['changes'][0]['id'], 'number': 7, 'branch': BRANCH, 'base': 'main',
                       'parent': {'id': TRAIL_ID}, 'mergeability': support.ChecksTests().snapshot(),
                       'actions': {'merge': {'state': 'enabled'}}}
        self.client.change_detail.return_value = self.detail
        self.client.command_json.side_effect = self.command
        self.target = {'repository': URL, 'mode': 'native', 'repo_id': REPO_ID, 'api_url': API, 'context': 'work',
                       'trail_id': TRAIL_ID, 'change_id': self.detail['id'], 'change_number': 7,
                       'branch': BRANCH, 'base': 'main', 'head': HEAD, 'base_head': BASE, 'tree': TREE,
                       'authority_repository': URL, 'authority_branch': BRANCH, 'branch_mode': 'native'}
        self.verification = {'schema_version': 1, 'purpose': 'verification', 'producer_id': 'getzilla-ci',
            'policy_digest': '1' * 64, 'plan_digest': '2' * 64, 'target': self.target, 'attempt_id': 'attempt-123',
            'issued_at': 90, 'expires_at': 190, 'checks': [{'name': 'verify', 'status': 'passed', 'evidence_sha256': '3' * 64}],
            'review': {'head': HEAD, 'independent': True, 'status': 'passed', 'unresolved_threads': 0}, 'publication': None}
        self.receipt = {'check_suite': {'id': 'suite-1', 'key': 'getzilla-ci', 'external_id': 'attempt-123'},
                        'results': [{'check_run': {'id': 'run-1', 'key': 'verify', 'status': 'completed', 'conclusion': 'success'},
                                     'outcome': 'created'}]}
        self.proof = self.signed({**self.verification, 'purpose': 'accepted-check', 'publication': self.receipt})

    def signed(self, payload):
        payload = copy.deepcopy(payload)
        return {'payload': payload, 'signature': base64.b64encode(self.key.sign(canonical(payload))).decode()}

    def command(self, args, **kwargs):
        if args[0] == 'trail':
            return self.trail()
        self.merged = True
        return {'ok': True, 'mergeCommitSha': MERGED}

    def merge(self, **changes):
        args = dict(branch=BRANCH, base='main', base_head=BASE, proof=self.proof, request_id='merge-123')
        args.update(changes)
        return self.adapter.merge(TRAIL_ID, HEAD, **args)

    def posts(self):
        return [call for call in self.client.command_json.call_args_list if call.args[0][0] == 'api']

    def test_real_grant_uses_the_existing_merge_action_and_exact_entire_resource(self):
        import subprocess
        from getzilla import state
        with support.github_project() as root:
            subprocess.run(['git', 'remote', 'set-url', 'origin', URL], cwd=root, check=True)
            resource = URL + '#trails/' + TRAIL_ID
            state.add_approval(root, 'production', 'synthetic exact operation authorization', 5,
                               actions=['pull-request-merge'], resources=[resource])
            self.assertTrue(state.has_valid_approval(root, 'production', action='pull-request-merge', resource=resource))
            self.assertFalse(state.has_valid_approval(root, 'production', action='pull-request-merge',
                                                    resource=URL + '#trails/foreign'))

    def test_native_ordinary_merge_is_bound_and_never_deletes_the_branch(self):
        result = self.merge()
        self.assertEqual(result['status'], 'merged')
        self.assertFalse(result['upstream_verified'])
        self.assertFalse(result['hosted_e2e_verified'])
        [call] = self.posts()
        self.assertEqual(json.loads(call.kwargs['input_data']), {'expectedHeadSha': HEAD, 'bypass': False, 'deleteBranch': False})
        self.assertEqual(call.args[0][-1], f'/api/v1/repos/{REPO_ID}/trails/7/merge')
        self.authorizer.assert_called_with(self.root, 'production', action='pull-request-merge', resource=URL + '#trails/' + TRAIL_ID)

    def test_successful_duplicate_returns_original_without_another_merge(self):
        first = self.merge()
        self.detail['status'] = 'merged'
        again = self.merge()
        self.assertTrue(again['replayed'])
        self.assertEqual(again['merge_commit'], first['merge_commit'])
        self.assertEqual(len(self.posts()), 1)

    def test_unknown_write_never_retries(self):
        def timeout(args, **kwargs):
            if args[0] == 'api':
                raise EntireError('timeout', 'synthetic unavailable')
            return self.trail()
        self.client.command_json.side_effect = timeout
        with self.assertRaises(EntireError):
            self.merge()
        with self.assertRaisesRegex(EntireError, 'reconcil'):
            self.merge()
        self.assertEqual(len(self.posts()), 1)

    def test_post_success_without_confirmed_base_remains_unknown(self):
        self.adapter.remote_head.side_effect = lambda repo, branch: HEAD if branch == BRANCH else BASE
        with self.assertRaisesRegex(EntireError, 'reconcil'):
            self.merge()
        with self.assertRaisesRegex(EntireError, 'reconcil'):
            self.merge()
        self.assertEqual(len(self.posts()), 1)

    def test_display_checks_and_grants_do_not_substitute_for_signature(self):
        with self.assertRaises(EntireError):
            self.merge(proof={'payload': self.verification, 'signature': 'invalid'})
        self.assertFalse(self.posts())

    def test_every_source_and_authority_coordinate_is_bound(self):
        for field in self.target:
            with self.subTest(field=field):
                target = {**self.target, field: 'foreign'}
                proof = self.signed({**self.proof['payload'], 'target': target})
                with self.assertRaises(EntireError):
                    self.merge(proof=proof, request_id='target-' + field)
                self.assertFalse(self.posts())

    def test_wrong_producer_policy_plan_checks_review_and_expiry_refuse(self):
        variants = [dict(producer_id='other'), dict(policy_digest='9' * 64), dict(plan_digest='9' * 64),
                    dict(checks=[]), dict(expires_at=99), dict(expires_at=10000),
                    dict(review={'head': HEAD, 'independent': True, 'status': 'passed', 'unresolved_threads': 1}),
                    dict(purpose='verification', publication=None),
                    dict(review={'head': HEAD, 'independent': 1, 'status': 'passed', 'unresolved_threads': False})]
        for index, fields in enumerate(variants):
            with self.subTest(fields=fields), self.assertRaises(EntireError):
                self.merge(proof=self.signed({**self.proof['payload'], **fields}), request_id=f'variant-{index}')
        self.assertFalse(self.posts())

    def test_provider_blocker_never_selects_bypass(self):
        self.detail['actions']['merge'] = {'state': 'blocked'}
        self.detail['actions']['merge_with_bypass'] = {'state': 'enabled'}
        with self.assertRaises(EntireError):
            self.merge()
        self.assertFalse(self.posts())

    def test_source_or_base_drift_before_write_refuses(self):
        self.adapter.remote_head.side_effect = lambda *_: 'f' * 40
        with self.assertRaises(EntireError):
            self.merge()
        self.assertFalse(self.posts())

    def mirror(self, *, reader=True):
        self.repo = Repository(parse_remote(MIRROR), REPO_ID, API, 'private', None)
        self.client.discover.return_value = self.repo
        self.adapter.identity.return_value = self.repo.identity
        def upstream(repo, branch):
            return {'repository': repo, 'branch': branch,
                    'head': HEAD if branch == BRANCH else MERGED if self.merged else BASE}
        self.authority = replace(self.authority, upstream=upstream if reader else None)
        self.adapter.authority = self.authority
        self.target.update(repository=MIRROR, mode='mirror', authority_repository='https://github.com/team/repo',
                           branch_mode='github-upstream')
        self.proof = self.signed({**self.proof['payload'], 'target': self.target})

    def test_mirror_requires_independently_matching_upstream_and_confirms_it(self):
        self.mirror()
        result = self.merge()
        self.assertTrue(result['upstream_verified'])
        [call] = self.posts()
        self.assertNotIn('deleteBranch', json.loads(call.kwargs['input_data']))

    def test_mirror_ref_does_not_prove_github_without_qualified_reader(self):
        self.mirror(reader=False)
        with self.assertRaises(EntireError) as error:
            self.merge()
        self.assertEqual(error.exception.code, 'unsupported')
        self.assertFalse(self.posts())

    def test_mirror_wrong_upstream_branch_or_outage_refuses(self):
        self.mirror()
        self.adapter.authority = replace(self.authority, upstream=lambda repo, branch:
            {'repository': repo, 'branch': 'entire-local/' + branch, 'head': HEAD})
        with self.assertRaises(EntireError):
            self.merge()
        self.assertFalse(self.posts())

    def test_publisher_requires_signed_success_and_checks_the_sdk_outcome(self):
        upsert = mock.Mock(return_value=self.receipt)
        publisher = EntireCheckPublisher(self.root, self.authority, upsert=upsert, sign=self.key.sign)
        result = publisher.publish(self.target, self.signed(self.verification), 'publish-123')
        self.authority.verify(result, self.target)
        self.assertEqual(upsert.call_args.args[0], self.target)
        publisher.publish(self.target, self.signed(self.verification), 'publish-123')
        upsert.assert_called_once()

    def test_failed_check_cannot_reach_the_publisher(self):
        upsert = mock.Mock(return_value=self.receipt)
        publisher = EntireCheckPublisher(self.root, self.authority, upsert=upsert, sign=self.key.sign)
        verification = copy.deepcopy(self.verification)
        verification['checks'][0]['status'] = 'failed'
        with self.assertRaises(EntireError):
            publisher.publish(self.target, self.signed(verification), 'publish-failed')
        upsert.assert_not_called()

    def test_unknown_or_stale_publisher_response_cannot_create_acceptance_or_retry(self):
        receipt = copy.deepcopy(self.receipt)
        receipt['results'][0]['outcome'] = 'ignored_stale'
        upsert = mock.Mock(return_value=receipt)
        publisher = EntireCheckPublisher(self.root, self.authority, upsert=upsert, sign=self.key.sign)
        for _ in range(2):
            with self.assertRaises(EntireError):
                publisher.publish(self.target, self.signed(self.verification), 'publish-unknown')
        upsert.assert_called_once()
