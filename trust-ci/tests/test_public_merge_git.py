"""Exercise commit-time comparisons against real Git refs in a disposable bare repository."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from dataclasses import asdict, replace
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from adaptive_trust_ci.public_admission import Decision, Selector, _integration_blockers
from adaptive_trust_ci.public_merge import (
    DispatchFence, Receipt, SignedReview, Snapshot, execute, reconcile, review_bytes, review_payload,
)


class GitTransactionTests(unittest.TestCase):
    """The fixed clock and admission decision model dependencies outside Git."""

    def git(self, *args, stdin=None, check=True):
        return subprocess.run(
            ['git', '-c', 'user.name=Test', '-c', 'user.email=fixture@example.invalid', *args],
            cwd=self.repo, input=stdin, capture_output=True, text=True, check=check, timeout=10,
        )

    def setUp(self):
        temp = TemporaryDirectory(prefix='getzilla-local-merge-')
        self.addCleanup(temp.cleanup)
        self.repo = Path(temp.name)
        self.git('init', '--bare', '-q', '--initial-branch=main')
        tree = self.git('mktree', stdin='').stdout.strip()
        self.base = self.git('commit-tree', tree, '-m', 'base').stdout.strip()
        self.head = self.git('commit-tree', tree, '-p', self.base, '-m', 'proposed change').stdout.strip()
        self.merged = self.git('commit-tree', tree, '-p', self.base, '-p', self.head, '-m', 'candidate merge').stdout.strip()
        self.git('update-ref', 'refs/heads/main', self.base)
        self.git('update-ref', 'refs/heads/candidate', self.head)
        self.git('update-ref', 'refs/decisions/generation', self.base)
        self.git('update-ref', 'refs/clock/sample', self.base)
        self.fence = DispatchFence.create(self.repo / 'dispatch.sqlite')
        self.selector = Selector('example/project', 11, 7, self.base, self.head, tree, 37, 1)
        self.start = datetime(2026, 11, 4, tzinfo=timezone.utc)
        self.now = self.start
        self.owner = 42
        key = Ed25519PrivateKey.generate()
        self.private = key
        self.pubkey = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.proof = 'd' * 64
        payload = review_payload(self.selector, self.owner, 1, 'approve', self.start, evidence_id=self.proof, target_generation=1, merge_oid=self.merged)
        self.review = SignedReview(payload, base64.b64encode(key.sign(review_bytes(payload))).decode('ascii'))
        self.before_write = lambda: None
        self.lost_result = False
        self.after_time_read = lambda: None

    def ref(self, name):
        return self.git('rev-parse', '--verify', name).stdout.strip()

    def snapshot(self, selector):
        return Snapshot(self.ref('refs/decisions/generation'), selector, 'main', True, (self.review,), True, self.proof,
                        evidence_unique=True, pending_key=None, merge_oid=self.merged, target_generation=1)

    def lookup(self, key):
        ref = self.git('rev-parse', '--verify', 'refs/receipts/' + key, check=False)
        if ref.returncode:
            return 'unknown'
        data = json.loads(self.git('cat-file', 'blob', ref.stdout.strip()).stdout)
        data['selector'] = Selector(**data['selector'])
        return Receipt(**data)

    def commit_once(self, ticket):
        prior = self.lookup(ticket.key)
        if isinstance(prior, Receipt):
            return replace(prior, state='already-merged')

        def receipt(state):
            return Receipt(key=ticket.key, selector=ticket.selector, evidence_id=ticket.evidence_id,
                           target_generation=ticket.target_generation, merge_oid=ticket.merge_oid, state=state)

        self.before_write()
        # The clock generation is a controlled fixture. Moving it after this read must
        # invalidate the Git transaction. It does not establish a real-time GitHub lease.
        clock_stamp = self.ref('refs/clock/sample')
        if not ticket.valid_from <= self.now <= ticket.valid_until:
            return receipt('expired')
        self.after_time_read()
        tree = self.ref(ticket.merge_oid + '^{tree}')
        def bounded_git(root, args, **kwargs):
            result = self.git(*args, check=False)
            return result.stdout.encode() if result.returncode == 0 else None
        core = SimpleNamespace(git=SimpleNamespace(run_git_bounded=bounded_git))
        if _integration_blockers(core, self.repo, ticket.selector,
                {'merge_sha': ticket.merge_oid, 'tree_sha': tree, 'report': {}}):
            return receipt('stale')
        confirmed = receipt('merged')
        blob = self.git('hash-object', '-w', '--stdin', stdin=json.dumps(asdict(confirmed), sort_keys=True)).stdout.strip()
        commands = '\n'.join([
            'start', f'verify refs/decisions/generation {ticket.revision}',
            f'verify refs/clock/sample {clock_stamp}',
            f'verify refs/heads/candidate {ticket.selector.head_sha}',
            f'update refs/heads/main {ticket.merge_oid} {ticket.selector.base_sha}',
            f'create refs/receipts/{ticket.key} {blob}', 'prepare', 'commit', '',
        ])
        result = self.git('update-ref', '--stdin', stdin=commands, check=False)
        if result.returncode:
            return receipt('stale')
        if self.lost_result:
            raise TimeoutError('local transaction committed before simulated reply loss')
        return confirmed

    def run_once(self):
        def verifier(selector, observed):
            return Decision(selector == self.selector and observed <= self.start + timedelta(hours=1), ())
        verifier.evidence_id = self.proof
        return execute(self, verifier, selector=self.selector, owner_id=self.owner, owner_key=self.pubkey, clock=lambda: self.now)

    def test_approved_change_updates_only_local_main_and_records_one_receipt(self):
        self.assertEqual(self.run_once().state, 'merged')
        self.assertEqual(self.ref('refs/heads/main'), self.merged)
        self.assertEqual(len(self.git('for-each-ref', 'refs/receipts').stdout.splitlines()), 1)
        self.assertEqual(self.git('rev-parse', self.merged+'^2').stdout.strip(), self.head)

    def test_revision_change_prevents_main_and_receipt_updates(self):
        self.before_write = lambda: self.git('update-ref', 'refs/decisions/generation', self.head)
        self.assertEqual(self.run_once().state, 'blocked')
        self.assertEqual(self.ref('refs/heads/main'), self.base)
        self.assertEqual(self.git('for-each-ref','refs/receipts').stdout, '')

    def test_expiry_at_local_writer_leaves_main_untouched(self):
        self.before_write = lambda: setattr(self, 'now', self.start + timedelta(seconds=6))
        self.assertEqual(self.run_once().state, 'blocked')
        self.assertEqual(self.ref('refs/heads/main'), self.base)
        self.assertEqual(self.git('for-each-ref','refs/receipts').stdout, '')

    def test_head_change_between_read_and_write_fails_the_atomic_comparison(self):
        self.before_write = lambda: self.git('update-ref', 'refs/heads/candidate', self.merged)
        self.assertEqual(self.run_once().state, 'blocked')
        self.assertEqual(self.ref('refs/heads/main'), self.base)
        self.assertEqual(self.git('for-each-ref','refs/receipts').stdout, '')

    def test_base_change_between_read_and_write_keeps_the_intervening_commit(self):
        self.before_write = lambda: self.git('update-ref', 'refs/heads/main', self.head)
        self.assertEqual(self.run_once().state, 'blocked')
        self.assertEqual(self.ref('refs/heads/main'), self.head)
        self.assertEqual(self.git('for-each-ref','refs/receipts').stdout, '')

    def test_controlled_clock_jump_after_python_precheck_invalidates_git_transaction(self):
        def advance_fixture_clock():
            self.now += timedelta(seconds=60)
            self.git('update-ref', 'refs/clock/sample', self.head)
        self.after_time_read = advance_fixture_clock
        self.assertEqual(self.run_once().state, 'blocked')
        self.assertEqual(self.ref('refs/heads/main'), self.base)
        self.assertEqual(self.git('for-each-ref', 'refs/receipts').stdout, '')

    def test_unknown_result_reconciles_from_the_git_receipt_without_second_write(self):
        self.lost_result = True
        result = self.run_once()
        self.assertEqual(result.state, 'unknown')
        self.assertEqual(reconcile(self, result.ticket).state, 'already-merged')
        self.assertEqual(self.ref('refs/heads/main'), self.merged)
        self.assertEqual(len(self.git('for-each-ref', 'refs/receipts').stdout.splitlines()), 1)

    def diverged(self, *, substitute=False, conflict=False):
        common = self.git('hash-object', '-w', '--stdin', stdin='common\n').stdout.strip()
        base_blob = self.git('hash-object', '-w', '--stdin', stdin='base\n').stdout.strip()
        head_blob = self.git('hash-object', '-w', '--stdin', stdin='head\n').stdout.strip()
        ancestor_tree = self.git('mktree', stdin=f'100644 blob {common}\tcommon.txt\n').stdout.strip()
        ancestor = self.git('commit-tree', ancestor_tree, '-m', 'common ancestor').stdout.strip()
        base_tree = self.git('mktree', stdin=f'100644 blob {base_blob}\tbase.txt\n100644 blob {common}\tcommon.txt\n').stdout.strip()
        name = 'base.txt' if conflict else 'head.txt'
        head_tree = self.git('mktree', stdin=f'100644 blob {common}\tcommon.txt\n100644 blob {head_blob}\t{name}\n').stdout.strip()
        self.base = self.git('commit-tree', base_tree, '-p', ancestor, '-m', 'base').stdout.strip()
        self.head = self.git('commit-tree', head_tree, '-p', ancestor, '-m', 'head').stdout.strip()
        tree = head_tree if substitute or conflict else self.git('merge-tree', '--write-tree', self.base, self.head).stdout.strip()
        self.merged = self.git('commit-tree', tree, '-p', self.base, '-p', self.head, '-m', 'integration').stdout.strip()
        self.selector = replace(self.selector, base_sha=self.base, head_sha=self.head, tree_sha=head_tree)
        self.git('update-ref', 'refs/heads/main', self.base)
        self.git('update-ref', 'refs/heads/candidate', self.head)
        payload = review_payload(self.selector, self.owner, 1, 'approve', self.start,
                                 evidence_id=self.proof, target_generation=1, merge_oid=self.merged)
        self.review = SignedReview(payload, base64.b64encode(self.private.sign(review_bytes(payload))).decode())

    def test_real_diverged_merge_retains_base_and_head_files(self):
        self.diverged()
        self.assertEqual(self.run_once().state, 'merged')
        self.assertEqual(self.git('ls-tree', '-r', '--name-only', 'refs/heads/main').stdout.splitlines(),
                         ['base.txt', 'common.txt', 'head.txt'])
        self.assertEqual(len(self.git('for-each-ref', 'refs/receipts').stdout.splitlines()), 1)

    def test_even_owner_signed_substituted_tree_cannot_drop_base(self):
        self.diverged(substitute=True)
        self.assertEqual(self.run_once().state, 'blocked')
        self.assertEqual(self.ref('refs/heads/main'), self.base)
        self.assertEqual(self.git('for-each-ref', 'refs/receipts').stdout, '')

    def test_conflict_cannot_write_a_resolution_without_new_candidate(self):
        self.diverged(conflict=True)
        self.assertEqual(self.run_once().state, 'blocked')
        self.assertEqual(self.ref('refs/heads/main'), self.base)
        self.assertEqual(self.git('for-each-ref', 'refs/receipts').stdout, '')
