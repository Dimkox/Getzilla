"""All authority, keys, target PRs and provider effects in these tests are local fixtures."""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, replace
from contextlib import contextmanager
from threading import Barrier, Event
from datetime import datetime, timedelta, timezone
import base64
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from adaptive_trust_ci.public_merge import (
    BoundPublicVerifier, DispatchFence, Receipt, Snapshot, SignedReview, execute, reconcile, review_bytes, review_payload,
)
from adaptive_trust_ci.public_admission import Decision, Evidence

NOW = datetime(2026, 11, 4, 4, tzinfo=timezone.utc)
SHA = 'a' * 40
OWNER = 17
MERGE = 'd' * 40


def model_evidence(merge_oid, variant=None):
    return Evidence({}, {}, {'merge_sha': merge_oid}, {} if variant is None else {'variant': variant})


def model_evidence_id(merge_oid):
    return hashlib.sha256(review_bytes(model_evidence(merge_oid).__dict__)).hexdigest()


EVIDENCE = model_evidence_id(MERGE)


def model_verifier(check, merge_oid, horizon, *, variant=None):
    """Non-authorizing protocol double at evaluate, never a runtime dispatch bypass."""
    producer = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return BoundPublicVerifier(None, SimpleNamespace(public_key_pem=producer, check=check, horizon=horizon),
                               model_evidence(merge_oid, variant))


def controlled_evaluate(client, authority, selector, evidence, *, now, **kwargs):
    decision = authority.check(selector, now)
    return Decision(decision.eligible, decision.blockers, valid_until=authority.horizon)


@contextmanager
def controlled_canonical(check, merge_oid, horizon, *, variant=None):
    with patch('adaptive_trust_ci.public_admission.evaluate', side_effect=controlled_evaluate):
        yield model_verifier(check, merge_oid, horizon, variant=variant)


@dataclass(frozen=True)
class Selector:
    repository: str = 'example/repo'
    repository_id: int = 7
    pr_number: int = 42
    base_sha: str = SHA
    head_sha: str = 'b' * 40
    tree_sha: str = 'c' * 40
    run_id: int = 21
    run_attempt: int = 1


class LocalBackend:
    """A deterministic, in-memory model of commit-time authority and keyed reconciliation."""

    def __init__(self, snapshot, db_path):
        self.fence = DispatchFence.create(db_path)
        self.current = snapshot
        self.now = NOW
        self.calls = []
        self.merges = []
        self.receipts = {}
        self.before_commit = lambda: None
        self.lose_reply = False
        self.in_doubt = set()

    def snapshot(self, selector):
        return self.current

    def lookup(self, key):
        if key in self.in_doubt:
            return 'unknown'
        return self.receipts.get(key, 'unknown')

    def commit_once(self, ticket):
        self.calls.append(ticket)
        self.before_commit()
        response = Receipt(ticket.key, ticket.selector, ticket.evidence_id, ticket.merge_oid, ticket.target_generation)
        if ticket.key in self.receipts:
            return replace(self.receipts[ticket.key], state='already-merged')
        if ticket.key in self.in_doubt:
            return 'unknown'
        if self.current.revision != ticket.revision or not self.current.is_open:
            return replace(response, state='stale')
        if not ticket.valid_from <= self.now <= ticket.valid_until:
            return replace(response, state='expired')
        self.merges.append(ticket.selector)
        self.receipts[ticket.key] = Receipt(ticket.key, ticket.selector, ticket.evidence_id,
                                             ticket.merge_oid, ticket.target_generation)
        self.current = replace(self.current, is_open=False, revision='closed')
        if self.lose_reply:
            raise TimeoutError('simulated lost receipt')
        return self.receipts[ticket.key]


class FinalMergeTests(TestCase):
    def setUp(self):
        self.selector = Selector()
        self.private = Ed25519PrivateKey.generate()
        self.pem = self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        temp = TemporaryDirectory(dir=Path(__file__).resolve().parents[2] / '.getzilla/runtime')
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'fence.db'
        self.backend = LocalBackend(Snapshot('v1', self.selector, 'main', True,
                                             (self.review(),), True, EVIDENCE, True, None, MERGE, 1), self.path)
        self.now = NOW
        self.decision = SimpleNamespace(eligible=True, blockers=())
        self.verify = Mock(return_value=self.decision)
        self.verify.evidence_id = EVIDENCE
        boundary = patch('adaptive_trust_ci.public_admission.evaluate', side_effect=controlled_evaluate)
        boundary.start()
        self.addCleanup(boundary.stop)

    def review(self, sequence=1, action='approve', selector=None, owner=OWNER, key=None, **kw):
        payload = review_payload(selector or self.selector, owner, sequence, action,
                                 kw.pop('issued_at', NOW), evidence_id=kw.pop('evidence_id', EVIDENCE), merge_oid=kw.pop('merge_oid', MERGE),
                                 target_generation=kw.pop('target_generation', 1), **kw)
        return SignedReview(payload, base64.b64encode((key or self.private).sign(review_bytes(payload))).decode())

    def run_controller(self, **kwargs):
        variant = None if self.verify.evidence_id == EVIDENCE else self.verify.evidence_id
        verifier = model_verifier(self.verify, MERGE, self.now + timedelta(seconds=5), variant=variant)
        return execute(self.backend, verifier, owner_id=OWNER, owner_key=self.pem,
                       selector=self.selector, clock=lambda: self.now, **kwargs)

    def change(self, **kwargs):
        self.backend.current = replace(self.backend.current, **kwargs)

    def blocked(self, **kwargs):
        result = self.run_controller(**kwargs)
        self.assertEqual(result.state, 'blocked', result)
        self.assertFalse(self.backend.calls, result)
        self.assertFalse(self.backend.merges, result)
        return result

    def test_verified_owner_approval_merges_once_and_validates_dispatch_horizon(self):
        self.assertEqual(self.run_controller().state, 'merged')
        self.assertEqual([c.args for c in self.verify.call_args_list],
                         [(self.selector, NOW), (self.selector, NOW + timedelta(seconds=5))])
        self.assertEqual(self.backend.merges, [self.selector])
        self.assertEqual(self.backend.calls[0].evidence_id, EVIDENCE)

    def test_no_approval(self):
        self.change(reviews=())
        self.assertEqual(self.blocked().reason, 'owner-decision-missing')

    def test_latest_revocation_controls(self):
        self.change(reviews=(self.review(), self.review(2, 'revoke')))
        self.assertEqual(self.blocked().reason, 'owner-decision-revoked')

    def test_fresh_approval_after_revocation(self):
        self.change(reviews=(self.review(), self.review(2, 'revoke'), self.review(3)))
        self.assertEqual(self.run_controller().state, 'merged')

    def test_forged_owner(self):
        self.change(reviews=(self.review(key=Ed25519PrivateKey.generate()),))
        self.assertEqual(self.blocked().reason, 'owner-signature-invalid')

    def test_wrong_pinned_owner_id(self):
        self.change(reviews=(self.review(owner=OWNER + 1),))
        self.blocked()

    def test_review_sequence_gaps_duplicates_and_unsorted(self):
        for seq in ([2], [1, 1], [1, 3], [2, 1]):
            with self.subTest(sequence=seq):
                self.change(reviews=tuple(self.review(s) for s in seq))
                self.blocked()

    def test_incomplete_pagination_and_unavailable_authority(self):
        self.change(complete=False)
        self.blocked()
        self.backend.snapshot = Mock(side_effect=TimeoutError)
        self.blocked()

    def test_latest_approval_bound_to_pr_source_and_current_attempt(self):
        for field, value in dict(repository='other/repo', repository_id=8, pr_number=91,
                                 base_sha='1'*40, head_sha='2'*40, tree_sha='3'*40,
                                 run_id=11, run_attempt=2).items():
            with self.subTest(field=field):
                self.change(reviews=(self.review(selector=replace(self.selector, **{field: value})),))
                self.blocked()

    def test_pr_closed_retargeted_and_selector_stale(self):
        snap = self.backend.current
        for change in (dict(is_open=False), dict(base_ref='staging'),
                       dict(selector=replace(self.selector, run_attempt=2))):
            self.backend.current = replace(snap, **change)
            self.blocked()

    def test_latest_approval_must_be_for_same_evidence(self):
        self.change(reviews=(self.review(evidence_id='1'*64),))
        self.blocked()

    def test_evaluator_bound_to_expected_evidence(self):
        self.verify.evidence_id = 'e'*64
        self.blocked()

    def test_missing_and_unavailable_admission_are_blocked(self):
        self.verify.return_value = SimpleNamespace(eligible=False, blockers=('feed-expired',))
        self.blocked()
        self.verify.side_effect = OSError
        self.blocked()

    def test_feed_expiring_within_dispatch_window_blocks(self):
        self.verify.side_effect = lambda _, t: SimpleNamespace(
            eligible=t <= NOW + timedelta(seconds=3), blockers=() if t <= NOW + timedelta(seconds=3) else ('expired',))
        self.blocked()

    def test_approval_expiry_clamps_ticket(self):
        self.change(reviews=(self.review(expires_at=NOW + timedelta(seconds=1)),))
        self.assertEqual(self.run_controller().state, 'merged')
        self.assertEqual(self.backend.calls[0].valid_until, NOW + timedelta(seconds=1))

    def test_future_and_expired_owner_decisions(self):
        for review in (self.review(issued_at=NOW + timedelta(seconds=1)),
                       self.review(issued_at=NOW - timedelta(hours=2), expires_at=NOW - timedelta(seconds=1))):
            self.change(reviews=(review,))
            self.blocked()

    def test_backend_races_suppress_mutations(self):
        reviews = []
        for delta in (dict(selector=replace(self.selector, head_sha='d'*40)),
                      dict(selector=replace(self.selector, base_sha='d'*40)),
                      dict(selector=replace(self.selector, run_attempt=2)),
                      dict(reviews=(self.review(), self.review(2,'revoke'))),
                      dict(evidence_id='e'*64), dict(is_open=False)):
            with self.subTest(delta=delta):
                reviews.append(self.review(len(reviews) + 1))
                self.change(revision='v1', selector=self.selector, is_open=True,
                            reviews=tuple(reviews), evidence_id=EVIDENCE)
                self.backend.before_commit = lambda: self.change(revision='v2', **delta)
                self.assertEqual(self.run_controller().reason, 'atomic-backend-stale')
                self.assertEqual(self.backend.merges, [])

    def test_expiry_during_commit_does_not_merge(self):
        self.backend.now += timedelta(seconds=5, microseconds=1)
        self.assertEqual(self.run_controller().state, 'blocked')
        self.assertFalse(self.backend.merges)

    def test_wall_clock_discontinuity_and_slow_evaluation(self):
        for delta in (-1, 6):
            with self.subTest(delta=delta):
                self.now = NOW
                def verify(*_):
                    self.now = NOW + timedelta(seconds=delta)
                    return self.decision
                self.verify.side_effect = verify
                self.blocked()

    def test_deny_naive_clock_oversize_or_negative_window(self):
        for window in (timedelta(seconds=-1), timedelta(seconds=5, microseconds=1)):
            self.blocked(window=window)
        self.now = NOW.replace(tzinfo=None)
        self.blocked()

    def test_lost_reply_is_unknown_and_same_key_is_reconciled(self):
        self.backend.lose_reply = True
        result = self.run_controller()
        self.assertEqual(result.state, 'unknown')
        self.assertEqual(len(self.backend.calls), 1)
        self.assertEqual(reconcile(self.backend, result.ticket).state, 'already-merged')
        self.assertEqual(self.run_controller().state, 'blocked')
        self.assertEqual(len(self.backend.calls), 1)
        self.assertEqual(len(self.backend.merges), 1)

    def test_unrecognized_commit_reply_is_unknown(self):
        self.backend.commit_once = Mock(return_value='ok')
        self.assertEqual(self.run_controller().state, 'unknown')
        self.assertEqual(self.backend.commit_once.call_count, 1)

    def test_unresolved_dispatch_is_never_reissued_by_reconciliation(self):
        self.backend.commit_once = Mock(side_effect=TimeoutError)
        pending = self.run_controller()
        self.assertEqual(reconcile(self.backend, pending.ticket).state, 'unknown')
        self.assertEqual(self.backend.commit_once.call_count, 1)
        self.assertFalse(self.backend.merges)

    def test_reconciliation_read_failure_cannot_assert_nonmerge(self):
        self.backend.lookup = Mock(side_effect=TimeoutError)
        self.backend.commit_once = Mock(side_effect=TimeoutError)
        self.assertEqual(reconcile(self.backend, self.run_controller().ticket).state, 'unknown')

    def test_mutating_approval_payload_invalidates_signature(self):
        item = self.review()
        item.payload['decision'] = 'revoke'
        self.change(reviews=(item,))
        self.blocked()

    def test_tampered_intermediate_review_is_detected(self):
        forged = self.review(sequence=1, key=Ed25519PrivateKey.generate())
        self.change(reviews=(forged, self.review(sequence=2)))
        self.blocked()

    def test_ambiguous_evidence_for_one_attempt_is_blocked_on_every_invocation(self):
        self.change(evidence_unique=False)
        self.blocked()
        self.blocked()

    def test_generation_or_proposed_merge_drift_requires_new_decision(self):
        self.change(target_generation=3)
        self.blocked()
        self.change(target_generation=1, merge_oid='5' * 40)
        self.blocked()

    def test_regressing_owner_decision_time_is_not_an_approval(self):
        self.change(reviews=(self.review(1), self.review(2, issued_at=NOW - timedelta(minutes=1))))
        self.blocked()

    def test_restart_and_new_approval_cannot_bypass_unknown_previous_dispatch(self):
        self.backend.commit_once = Mock(side_effect=TimeoutError)
        first = self.run_controller()
        self.assertEqual(first.state, 'unknown')
        self.change(revision='v2', reviews=(self.review(1), self.review(2)))
        self.backend.fence = DispatchFence(self.path)
        second = self.run_controller()
        self.assertEqual(second.state, 'unknown')
        self.assertEqual(self.backend.commit_once.call_count, 1)
        self.assertEqual(reconcile(self.backend, first.ticket).state, 'unknown')
        self.assertEqual(self.run_controller().state, 'unknown')
        self.assertEqual(self.backend.commit_once.call_count, 1)

    def test_definitive_no_effect_releases_only_after_authenticated_lookup(self):
        self.backend.commit_once = Mock(side_effect=TimeoutError)
        first = self.run_controller()
        self.backend.lookup = Mock(return_value='not-merged')
        # Bare strings do not identify which PR and dispatched request had no effect.
        self.assertEqual(reconcile(self.backend, first.ticket).state, 'unknown')
        t = first.ticket
        self.backend.lookup.return_value = Receipt(t.key, t.selector, t.evidence_id, t.merge_oid,
                                                  t.target_generation, 'not-merged')
        self.assertEqual(reconcile(self.backend, t).state, 'not-merged')
        self.assertEqual(self.run_controller().reason, 'owner-decision-already-used')
        self.assertEqual(self.backend.commit_once.call_count, 1)

    def test_replay_after_restart_and_old_receipt_cannot_release_a_new_grant(self):
        self.backend.commit_once = Mock(side_effect=TimeoutError)
        a = self.run_controller().ticket
        old_receipt = Receipt(a.key, a.selector, a.evidence_id, a.merge_oid, a.target_generation, 'not-merged')
        self.backend.lookup = Mock(return_value=old_receipt)
        self.assertEqual(reconcile(self.backend, a).state, 'not-merged')

        self.backend.fence = DispatchFence(self.path)
        self.now += timedelta(seconds=1)
        self.change(revision='new-read')
        self.assertEqual(self.run_controller().reason, 'owner-decision-already-used')
        self.assertEqual(self.backend.commit_once.call_count, 1)

        self.change(reviews=(self.review(1), self.review(2)))
        b = self.run_controller().ticket
        self.assertNotEqual(a.key, b.key)
        self.assertEqual(self.backend.commit_once.call_count, 2)
        self.assertEqual(reconcile(self.backend, b).state, 'unknown')
        self.assertEqual(reconcile(self.backend, a).state, 'not-merged')
        self.assertEqual(self.backend.fence.pending(self.selector), b)
        self.assertEqual(self.run_controller().state, 'unknown')
        self.assertEqual(self.backend.commit_once.call_count, 2)

    def test_lost_terminal_refusal_releases_fence_but_not_consumed_approval(self):
        for state in ('stale', 'expired', 'not-merged'):
            with self.subTest(state=state):
                self.setUp()
                self.backend.commit_once = Mock(side_effect=TimeoutError)
                pending = self.run_controller()
                ticket = pending.ticket
                self.backend.fence = DispatchFence(self.path)
                self.backend.lookup = Mock(return_value=Receipt(
                    ticket.key, ticket.selector, ticket.evidence_id, ticket.merge_oid,
                    ticket.target_generation, state))
                self.assertEqual(reconcile(self.backend, ticket).state, 'not-merged')
                self.assertIsNone(self.backend.fence.pending(self.selector))
                self.assertEqual(self.run_controller().reason, 'owner-decision-already-used')
                self.change(reviews=(self.review(1), self.review(2)))
                self.assertEqual(self.run_controller().state, 'unknown')
                self.assertEqual(self.backend.commit_once.call_count, 2)

    def test_commit_time_expiry_consumes_grant_even_when_no_ref_was_written(self):
        self.backend.now = NOW + timedelta(seconds=6)
        self.assertEqual(self.run_controller().reason, 'atomic-backend-expired')
        self.backend.now = self.now = NOW + timedelta(seconds=7)
        self.assertEqual(self.run_controller().reason, 'owner-decision-already-used')
        self.assertEqual(len(self.backend.calls), 1)
        self.assertFalse(self.backend.merges)

    def test_mismatched_backend_receipts_never_clear_pending_dispatch(self):
        self.backend.commit_once = Mock(return_value='merged')
        result = self.run_controller()
        self.assertEqual(result.state, 'unknown')
        t = result.ticket
        good = Receipt(t.key, t.selector, t.evidence_id, t.merge_oid, t.target_generation)
        for change in (dict(key='e'*64), dict(selector=replace(self.selector, pr_number=12)),
                       dict(merge_oid='e'*40), dict(evidence_id='0'*64), dict(target_generation=2)):
            self.backend.lookup = Mock(return_value=replace(good, **change))
            self.assertEqual(reconcile(self.backend, t).state, 'unknown')
        self.assertEqual(self.run_controller().state, 'unknown')
        self.assertEqual(self.backend.commit_once.call_count, 1)

    def test_external_pending_receipt_blocks_dispatch_even_with_a_new_local_fence(self):
        self.change(pending_key='e' * 64)
        self.assertEqual(self.run_controller().state, 'unknown')
        self.assertFalse(self.backend.calls)

    def test_unavailable_fence_cannot_reinitialize_lost_state(self):
        self.path.unlink()
        with self.assertRaises(Exception):
            DispatchFence(self.path)
        self.blocked()
        self.assertFalse(self.path.exists())

    def test_concurrent_workers_claim_one_pr_once(self):
        ready, release = Barrier(2, timeout=3), Event()
        snap = self.backend.current
        def snapshot(_):
            ready.wait()
            return snap
        self.backend.snapshot = snapshot
        self.backend.before_commit = lambda: release.wait(4)
        with ThreadPoolExecutor(max_workers=2) as workers:
            futures = [workers.submit(self.run_controller) for _ in range(2)]
            try:
                done, _ = wait(futures, timeout=3, return_when=FIRST_COMPLETED)
                self.assertEqual(len(done), 1)
                self.assertEqual(done.pop().result().state, 'unknown')
            finally:
                release.set()
            self.assertEqual(sorted(f.result().state for f in futures), ['merged', 'unknown'])
        self.assertEqual(self.backend.merges, [self.selector])
