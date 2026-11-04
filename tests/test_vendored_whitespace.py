"""Exact vendored whitespace proof retains all three Git-layer boundaries."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.getzilla'))

from getzilla.verification_dispositions import Dispositions, DispositionError  # noqa: E402
from tests.test_verification_dispositions import DispositionTests, digest  # noqa: E402

CATALOG = '.getzilla/config/vendored-source-catalog.json'
PROOF = 'engineering/vendor-custody/whitespace.json'
REVIEW = 'engineering/vendor-custody/custody.md'


def git_hash(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw,
                        usedforsecurity=False).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


class VendoredWhitespaceTests(unittest.TestCase):
    setUp = DispositionTests.setUp
    git = DispositionTests.git
    write = DispositionTests.write
    commit = DispositionTests.commit
    policy = DispositionTests.policy
    range_check = DispositionTests.range_check
    summary = DispositionTests.summary

    def vendor(self, content=b'exact upstream text \n', *, rules=None):
        blob = git_hash('blob', content)
        entries = [{'mode': '100644', 'name': 'source.md', 'oid': blob}]
        tree_raw = b'100644 source.md\0' + bytes.fromhex(blob)
        tree = git_hash('tree', tree_raw)
        commit_raw = ('tree ' + tree + '\nauthor Fixture <fixture@example.invalid> 1 +0000\n'
                      'committer Fixture <fixture@example.invalid> 1 +0000\n\npinned fixture\n')
        revision = git_hash('commit', commit_raw.encode())
        self.path = 'vendor/raw/' + digest(content) + '.txt'
        self.write(self.path, content)
        inventory = 'vendor/inventory.json'
        inventory_doc = {'binding': {'source_commit': revision}, 'files': [
            {'path': 'skill/SKILL.md', 'sha256': digest(content), 'mode': 0o644, 'bytes': len(content)}]}
        self.write(inventory, encoded(inventory_doc))
        self.catalog = {'schema_version': 1, 'owners': [{
            'id': 'fixture-vendor', 'root': 'vendor/raw',
            'inventory': {'path': inventory, 'sha256': digest(encoded(inventory_doc))},
            'repository': 'https://github.com/example/vendor', 'revision': revision,
            'commit': commit_raw, 'trees': [{'oid': tree, 'entries': entries}]}],
            'files': [{'path': self.path, 'sha256': digest(content), 'mode': '100644',
                       'owner': 'fixture-vendor', 'target_path': 'skill/SKILL.md',
                       'upstream_path': 'source.md', 'upstream_blob': blob}]}
        self.write(CATALOG, encoded(self.catalog))
        self.write(REVIEW, b'Independent custody facts only; not an authenticated approval.\n')
        self.rules = rules or [{'line': 1, 'rule': 'trailing-whitespace'}]
        self.proof = {'schema_version': 1, 'kind': 'immutable-vendored-whitespace-custody',
                      'catalog_sha256': digest(encoded(self.catalog)),
                      'review': {'path': REVIEW, 'sha256': digest((self.root / REVIEW).read_bytes())},
                      'files': [{'path': self.path, 'sha256': digest(content), 'mode': '100644',
                                 'diagnostics': self.rules}]}
        self.write(PROOF, encoded(self.proof))
        self.entries = [{'id': 'vendor-' + str(i), 'check': 'git-diff-check',
                         'kind': 'immutable-vendored-whitespace', 'rule': rule['rule'],
                         'path': self.path, 'sha256': digest(content), 'mode': '100644',
                         'line': rule['line'], 'reason': 'Preserve exact pinned upstream bytes.',
                         'catalog': {'path': CATALOG, 'sha256': digest(encoded(self.catalog))},
                         'evidence': {'path': PROOF, 'sha256': digest(encoded(self.proof))}}
                        for i, rule in enumerate(self.rules)]
        self.policy(self.entries)
        self.git('add', '.')
        for path in self.root.rglob('*'):
            if path.is_file() and '.git' not in path.parts:
                path.chmod(0o644)

    def test_exact_proof_retains_raw_error_and_classifies_worktree_index_and_head(self):
        self.vendor()
        self.commit()
        result = self.range_check()
        self.assertEqual(result.status, 'pass', result.to_dict())
        raw = next(x for x in result.details if x.get('observation'))
        self.assertEqual((raw['severity'], raw['effective_severity']), ('error', 'info'))
        self.assertEqual(self.summary(result)['disposed'], 1)
        policy = Dispositions(self.root)
        for layer in ('worktree', 'index', 'HEAD'):
            self.assertIsNotNone(policy.whitespace(self.path, 1, policy.snapshots(layer), 'trailing-whitespace'))

    def test_each_proof_layer_is_required_not_just_worktree_claims(self):
        self.vendor()
        policy = Dispositions(self.root)
        self.assertIsNone(policy.whitespace(self.path, 1, policy.snapshots('HEAD'), 'trailing-whitespace'))
        self.commit()
        for proof_path in (CATALOG, PROOF, REVIEW, 'vendor/inventory.json'):
            with self.subTest(path=proof_path):
                policy = Dispositions(self.root)
                snapshots = policy.snapshots('HEAD')
                snapshots[proof_path] = (b'foreign', '100644')
                self.assertIsNone(policy.whitespace(self.path, 1, snapshots, 'trailing-whitespace'))

    def test_missing_changed_or_executable_sources_catalog_and_evidence_refuse(self):
        self.vendor()
        self.commit()
        for path in (self.path, CATALOG, PROOF, REVIEW, 'vendor/inventory.json'):
            target = self.root / path
            raw = target.read_bytes()
            for change in ('missing', 'bytes', 'mode'):
                with self.subTest(path=path, change=change):
                    if change == 'missing':
                        target.unlink()
                    elif change == 'bytes':
                        target.write_bytes(raw + b'changed')
                    else:
                        target.chmod(0o755)
                    with self.assertRaises(DispositionError):
                        Dispositions(self.root)
                    target.write_bytes(raw)
                    target.chmod(0o644)

    def test_rehashed_catalog_does_not_prove_foreign_owner_or_upstream_identity(self):
        self.vendor()
        original = json.loads(json.dumps(self.catalog))
        for field, value in (('owner', 'foreign'), ('upstream_path', 'absent.md'),
                             ('upstream_blob', 'b' * 40), ('target_path', 'foreign/SKILL.md')):
            with self.subTest(field=field):
                self.catalog = json.loads(json.dumps(original))
                self.catalog['files'][0][field] = value
                self.write(CATALOG, encoded(self.catalog))
                self.proof['catalog_sha256'] = digest(encoded(self.catalog))
                self.write(PROOF, encoded(self.proof))
                for entry in self.entries:
                    entry['catalog']['sha256'] = digest(encoded(self.catalog))
                    entry['evidence']['sha256'] = digest(encoded(self.proof))
                self.policy(self.entries)
                with self.assertRaises(DispositionError):
                    Dispositions(self.root)

    def test_new_diagnostic_and_unlisted_paths_stay_blocking(self):
        self.vendor()
        self.commit()
        policy = Dispositions(self.root)
        snapshots = policy.snapshots('HEAD')
        self.assertIsNone(policy.whitespace(self.path, 1, snapshots, 'space-before-tab'))
        self.assertIsNone(policy.whitespace('foreign.txt', 1, snapshots, 'trailing-whitespace'))
        self.assertIsNone(policy.whitespace(self.path, 2, snapshots, 'trailing-whitespace'))
        self.write('new.txt', b'new unreviewed whitespace \n')
        self.commit()
        result = self.range_check()
        self.assertEqual(result.status, 'fail')
        self.assertGreater(self.summary(result)['unresolved'], 0)

    def test_malformed_duplicate_and_forged_review_records_refuse(self):
        self.vendor()
        for mutation in ('unknown', 'duplicate', 'mode', 'line', 'review'):
            with self.subTest(mutation=mutation):
                proof = json.loads(json.dumps(self.proof))
                if mutation == 'unknown':
                    proof['approved'] = True
                elif mutation == 'duplicate':
                    proof['files'].append(proof['files'][0])
                elif mutation == 'mode':
                    proof['files'][0]['mode'] = '100755'
                elif mutation == 'line':
                    proof['files'][0]['diagnostics'][0]['line'] = 2
                else:
                    proof['review']['sha256'] = 'f' * 64
                self.write(PROOF, encoded(proof))
                entries = json.loads(json.dumps(self.entries))
                for entry in entries:
                    entry['evidence']['sha256'] = digest(encoded(proof))
                self.policy(entries)
                with self.assertRaises(DispositionError):
                    Dispositions(self.root)

    def test_actual_git_layers_refuse_changed_staged_or_head_blob(self):
        self.vendor()
        self.commit()
        original = (self.root / self.path).read_bytes()
        self.write(self.path, b'foreign staged whitespace \n')
        self.git('add', '--', self.path)
        self.write(self.path, original)
        result = self.range_check()
        self.assertEqual(result.status, 'fail', result.to_dict())
        self.assertTrue(any(item.get('observation') and item['layer'] == 'index'
                            and item['effective_severity'] == 'error' for item in result.details))
        self.git('commit', '-qm', 'foreign HEAD source')
        self.git('add', '--', self.path)
        result = self.range_check()
        self.assertEqual(result.status, 'fail', result.to_dict())
        self.assertTrue(any(item.get('observation') and item['layer'] == 'route'
                            and item['effective_severity'] == 'error' for item in result.details))

    def test_valid_updated_worktree_evidence_cannot_cover_stale_index_or_head_proof(self):
        self.vendor()
        self.commit()
        # Update only working review facts and their hash-bound references.
        # These claims are valid in the worktree, but cannot cover HEAD findings.
        self.write(REVIEW, b'Updated custody facts; still no authenticated approval.\n')
        self.proof['review']['sha256'] = digest((self.root / REVIEW).read_bytes())
        self.write(PROOF, encoded(self.proof))
        for entry in self.entries:
            entry['evidence']['sha256'] = digest(encoded(self.proof))
        self.policy(self.entries)
        result = self.range_check()
        self.assertEqual(result.status, 'fail', result.to_dict())
        self.assertEqual(self.summary(result)['disposed'], 0)
        policy = Dispositions(self.root)
        self.assertIsNone(policy.whitespace(self.path, 1, policy.snapshots('index'), 'trailing-whitespace'))
        self.assertIsNone(policy.whitespace(self.path, 1, policy.snapshots('HEAD'), 'trailing-whitespace'))

    def test_in_place_worktree_tamper_remains_an_actual_blocking_check(self):
        self.vendor()
        self.commit()
        self.write(self.path, b'changed working whitespace \n')
        result = self.range_check()
        self.assertEqual(result.status, 'fail', result.to_dict())
        self.assertTrue(any(item['code'] == 'disposition-config-invalid' for item in result.details))

    def test_rehashed_wrong_root_commit_and_tree_catalogs_refuse(self):
        self.vendor()
        original = json.loads(json.dumps(self.catalog))
        for mutation in ('root', 'commit', 'tree', 'duplicate', 'schema'):
            with self.subTest(mutation=mutation):
                self.catalog = json.loads(json.dumps(original))
                if mutation == 'root':
                    self.catalog['owners'][0]['root'] = 'other/raw'
                elif mutation == 'commit':
                    self.catalog['owners'][0]['commit'] += 'changed'
                elif mutation == 'tree':
                    self.catalog['owners'][0]['trees'][0]['entries'][0]['oid'] = 'a' * 40
                elif mutation == 'duplicate':
                    self.catalog['files'].append(self.catalog['files'][0])
                else:
                    self.catalog['schema_version'] = True
                self.write(CATALOG, encoded(self.catalog))
                self.proof['catalog_sha256'] = digest(encoded(self.catalog))
                self.write(PROOF, encoded(self.proof))
                for entry in self.entries:
                    entry['catalog']['sha256'] = digest(encoded(self.catalog))
                    entry['evidence']['sha256'] = digest(encoded(self.proof))
                self.policy(self.entries)
                with self.assertRaises(DispositionError):
                    Dispositions(self.root)

    def test_linked_or_hidden_index_proof_sources_refuse(self):
        self.vendor()
        self.commit()
        target = self.root / PROOF
        saved = target.read_bytes()
        foreign = self.root / 'foreign-proof.json'
        foreign.write_bytes(saved)
        target.unlink()
        os.link(foreign, target)
        with self.assertRaises(DispositionError):
            Dispositions(self.root)
        target.unlink()
        target.write_bytes(saved)
        self.git('update-index', '--assume-unchanged', '--', PROOF)
        with self.assertRaises(DispositionError):
            Dispositions(self.root)
        self.git('update-index', '--no-assume-unchanged', '--', PROOF)
        self.assertIsNotNone(Dispositions(self.root))
