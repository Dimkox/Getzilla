"""Integration of the signed producer contract and an independently signed owner decision."""
import base64
import copy
import hashlib
import secrets
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import test_public_admission as producer
from test_public_merge import LocalBackend, MERGE
from adaptive_trust_ci.public_merge import BoundPublicVerifier, Snapshot, SignedReview, execute, review_bytes, review_payload


class SignedAdmissionMergeTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db_path = Path(temp.name) / 'fence.db'
        self.fixture = producer.PublicAdmissionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.transport = producer.ProviderTransport(self.fixture.records)
        self.client = producer.GitHubClient(token=secrets.token_urlsafe(24), transport=self.transport)
        self.private = Ed25519PrivateKey.generate()
        self.pem = self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.clock = producer.NOW
        self.selector = self.fixture.selector

    def arrange(self, evidence=None):
        evidence = evidence or self.fixture.evidence()
        tree = self.fixture.git('merge-tree', '--write-tree', self.selector.base_sha,
                                self.selector.head_sha).splitlines()[0]
        merged = self.fixture.git('commit-tree', tree, '-p', self.selector.base_sha,
                                  '-p', self.selector.head_sha, '-m', 'tested integration')
        report = copy.deepcopy(evidence.report)
        report['source'].update(head_sha=merged, tree_sha=tree)
        payload = copy.deepcopy(evidence.binding['payload'])
        payload.update(schema_version=2, integration={'merge_sha': merged, 'tree_sha': tree,
            'report_sha256': hashlib.sha256(producer.canonical_json(report)).hexdigest()})
        evidence = producer.Evidence({'payload': payload, 'signature': self.fixture.signer.sign(payload)},
            evidence.report, {'merge_sha': merged, 'tree_sha': tree, 'report': report})
        verifier = BoundPublicVerifier(self.client, self.fixture.authority, evidence,
                                       snapshot_root=self.fixture.snapshot_root, candidate_root=self.fixture.candidate_root)
        payload = review_payload(self.selector, 12, 1, 'approve', self.clock, evidence_id=verifier.evidence_id,
                                 merge_oid=merged, target_generation=1)
        review = SignedReview(payload, base64.b64encode(self.private.sign(review_bytes(payload))).decode())
        backend = LocalBackend(Snapshot('initial', self.selector, 'main', True, (review,), True,
                                        verifier.evidence_id, True, None, merged, 1), self.db_path)
        backend.now = self.clock
        return verifier, backend

    def dispatch(self, verifier, backend):
        return execute(backend, verifier, owner_id=12, owner_key=self.pem, selector=self.selector,
                       clock=lambda: self.clock)

    def test_signed_owner_and_producer_with_exact_empty_candidate(self):
        evidence = self.fixture.evidence()
        verifier, backend = self.arrange(evidence)
        evidence.report.clear()
        self.assertEqual(self.dispatch(verifier, backend).state, 'merged')
        self.assertEqual(backend.merges, [self.selector])
        self.assertTrue(self.transport.calls)
        self.assertTrue(all(method == 'GET' and body is None for method, _, body in self.transport.calls))

    def test_applicable_osv_cannot_grant_a_merge_with_unqualified_dependencies(self):
        self.fixture.prepare_applicable_osv_evidence()
        self.selector = self.fixture.selector
        verifier, backend = self.arrange()
        self.assertEqual(self.dispatch(verifier, backend).state, 'blocked')
        self.assertFalse(backend.calls)

    def test_old_report_blocks_after_72h(self):
        self.clock += timedelta(hours=72, microseconds=1)
        verifier, backend = self.arrange()
        self.assertEqual(self.dispatch(verifier, backend).state, 'blocked')
        self.assertFalse(backend.calls)
        self.assertFalse(backend.merges)

    def advance_clock_on_first_read(self, backend):
        observed = self.clock + timedelta(seconds=9)
        request = self.transport.request

        def delayed_request(method, url, headers, body):
            if not self.transport.calls:
                self.clock = backend.now = observed
            return request(method, url, headers, body)

        self.transport.request = delayed_request
        return observed

    def test_slow_successful_verification_starts_a_fresh_dispatch_window(self):
        verifier, backend = self.arrange()
        observed = self.advance_clock_on_first_read(backend)
        self.assertEqual(self.dispatch(verifier, backend).state, 'merged')
        ticket, = backend.calls
        self.assertEqual(ticket.valid_from, observed)
        self.assertEqual(ticket.valid_until, observed + timedelta(seconds=5))

    def test_binding_expired_during_provider_reads_blocks_dispatch(self):
        self.fixture.binding_payload['expires_at'] = (self.clock + timedelta(seconds=8)).isoformat()
        verifier, backend = self.arrange()
        self.advance_clock_on_first_read(backend)
        self.assertEqual(self.dispatch(verifier, backend).state, 'blocked')
        self.assertFalse(backend.calls)

    def test_rechecking_does_not_extend_binding(self):
        self.fixture.binding_payload['expires_at'] = (self.clock + timedelta(seconds=2)).isoformat()
        verifier, backend = self.arrange()
        backend.now += timedelta(seconds=2, microseconds=1)
        result = self.dispatch(verifier, backend)
        self.assertEqual(result.state, 'blocked')
        self.assertEqual(result.reason, 'atomic-backend-expired')
        self.assertEqual(backend.calls[0].valid_until, self.clock + timedelta(seconds=2))
        self.assertFalse(backend.merges)

    def test_newer_attempt_at_source_overrides_approvable_snapshot(self):
        verifier, backend = self.arrange()
        self.fixture.records['/repos/independent/runner/actions/runs/100']['run_attempt'] = 3
        self.assertEqual(self.dispatch(verifier, backend).state, 'blocked')
        self.assertFalse(backend.calls)

    def test_published_time_can_be_earlier_than_database_download_time(self):
        # The shared freshness calculator also covers source publication for EPSS/Trivy.
        # The current signed admission spike separately restricts applicable feed families.
        self.fixture.prepare_applicable_osv_evidence()
        self.selector = self.fixture.selector
        report = self.fixture.report
        feed = report['checks'][1]['details'][0]['data_sources'][0]
        feed['source_id'] = 'epss'
        feed['acquisition']['source_published_at'] = (
            self.clock - timedelta(hours=72) + timedelta(seconds=2)).isoformat()
        verifier, _ = self.arrange()
        self.assertEqual(verifier.deadline(self.clock), self.clock + timedelta(seconds=2))

    def test_producer_and_owner_must_not_share_the_same_public_key(self):
        self.fixture.signer = producer.Signer(self.private)
        self.fixture.authority = replace(self.fixture.authority, public_key_pem=self.pem)
        self.pem = self.pem.replace(b'\n', b'\r\n')
        verifier, backend = self.arrange()
        result = self.dispatch(verifier, backend)
        self.assertEqual(result.state, 'blocked')
        self.assertEqual(result.reason, 'producer-and-owner-share-key')
        self.assertFalse(backend.calls)
