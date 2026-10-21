"""R01 release state, R02 exact-source release gate, R03 artifact receipts without a hash cycle."""
from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / '.getzilla')]

from getzilla.release_state import (  # noqa: E402
    CheckRun, ReleaseStateError, artifact_receipt, decide_release, load_release_state, mark_publication,
    parse_release_state, record_artifact, validate_release_consistency,
)

COMMIT = 'c' * 40
TREE = 'd' * 40
REQUIRED = ('linux', 'windows')


def fixture() -> dict:
    return json.loads((ROOT / 'RELEASE_STATE.json').read_text(encoding='utf-8'))


class ReleaseStateTests(unittest.TestCase):
    def test_candidate_and_published_may_differ(self) -> None:
        state = load_release_state(ROOT / 'RELEASE_STATE.json')
        self.assertEqual(state.source_state, 'source_candidate')
        self.assertNotEqual(state.source_version, state.published_version)

    def test_audit_222_221_fixture_valid(self) -> None:
        state = parse_release_state(fixture())
        self.assertEqual((state.source_version, state.published_version), ('2.3.1', '2.3.0'))
        self.assertTrue(validate_release_consistency(state, ROOT).ok, validate_release_consistency(state, ROOT).errors)

    def test_version_mismatch_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('VERSION', 'PROJECT_STATE.json', 'README.md', 'RELEASE_STATE.json'):
                shutil.copyfile(ROOT / name, root / name)
            (root / 'VERSION').write_text('9.9.9\n', encoding='utf-8')
            result = validate_release_consistency(load_release_state(root / 'RELEASE_STATE.json'), root)
            self.assertFalse(result.ok)
            self.assertTrue(any('VERSION' in error for error in result.errors))

    def test_unknown_published_state_not_fabricated(self) -> None:
        data = fixture()
        data['published'] = None
        state = parse_release_state(data)
        self.assertIsNone(state.published_version)
        data['source']['state'] = 'released'
        with self.assertRaises(ReleaseStateError):
            parse_release_state(data)

    def test_schema_rejects_invalid_oid_or_state(self) -> None:
        for mutate in (lambda d: d['published'].__setitem__('commit', 'HEAD'),
                       lambda d: d['published'].__setitem__('tag', 'latest'),
                       lambda d: d['source'].__setitem__('state', 'shipping'),
                       lambda d: d.__setitem__('schema_version', 'release-state-v9')):
            data = copy.deepcopy(fixture())
            mutate(data)
            with self.subTest(data=json.dumps(data)[:80]), self.assertRaises(ReleaseStateError):
                parse_release_state(data)


class ReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = parse_release_state(fixture())
        self.green = [CheckRun(name, 'success', COMMIT) for name in REQUIRED]
        self.review = {'tree': TREE, 'status': 'pass'}

    def decide(self, **overrides):
        args = dict(source_commit=COMMIT, source_tree=TREE, required_checks=REQUIRED, checks=self.green,
                    review=self.review, existing_tags={})
        args.update(overrides)
        return decide_release(self.state, **args)

    def test_all_exact_checks_allow_without_publishing(self) -> None:
        decision = self.decide()
        self.assertTrue(decision.allowed, decision.reasons)
        self.assertEqual(decision.version, '2.3.1')

    def test_wrong_head_green_ci_rejected(self) -> None:
        decision = self.decide(checks=[CheckRun(name, 'success', 'e' * 40) for name in REQUIRED])
        self.assertIn('REQUIRED_CHECK_FOR_OTHER_HEAD:linux', decision.reasons)

    def test_review_for_different_tree_rejected(self) -> None:
        self.assertIn('REVIEW_NOT_BOUND_TO_SOURCE_TREE', self.decide(review={'tree': 'f' * 40, 'status': 'pass'}).reasons)
        self.assertIn('REVIEW_MISSING', self.decide(review=None).reasons)

    def test_required_skipped_job_rejected(self) -> None:
        for conclusion in ('skipped', 'cancelled', None, 'neutral'):
            checks = [CheckRun('linux', 'success', COMMIT), CheckRun('windows', conclusion, COMMIT)]
            with self.subTest(conclusion=conclusion):
                self.assertFalse(self.decide(checks=checks).allowed)

    def test_release_metadata_change_invalidates_approval(self) -> None:
        self.assertIn('SOURCE_CHANGED_AFTER_CHECKS', self.decide(metadata_tree_after_checks='9' * 40).reasons)

    def test_existing_tag_other_oid_rejected(self) -> None:
        self.assertIn('TAG_POINTS_TO_OTHER_SOURCE', self.decide(existing_tags={'v2.3.1': 'a' * 40}).reasons)
        self.assertTrue(self.decide(existing_tags={'v2.3.1': COMMIT}).allowed)


class ArtifactReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        state = parse_release_state(fixture())
        self.decision = decide_release(state, source_commit=COMMIT, source_tree=TREE, required_checks=REQUIRED,
                                       checks=[CheckRun(name, 'success', COMMIT) for name in REQUIRED],
                                       review={'tree': TREE, 'status': 'pass'}, existing_tags={})
        self.artifact = self.base / 'dist' / 'getzilla-2.3.1.zip'
        self.artifact.parent.mkdir()
        with zipfile.ZipFile(self.artifact, 'w') as archive:
            archive.writestr('VERSION', '2.3.1\n')

    def test_artifact_matches_selected_source(self) -> None:
        receipt = artifact_receipt(self.decision, self.artifact, built_from_tree=TREE, toolchain={'python': '3.12'})
        self.assertEqual(receipt.source_tree, TREE)
        with self.assertRaises(ReleaseStateError):
            artifact_receipt(self.decision, self.artifact, built_from_tree='9' * 40, toolchain={})

    def test_receipt_not_hashed_into_own_artifact(self) -> None:
        receipt = artifact_receipt(self.decision, self.artifact, built_from_tree=TREE, toolchain={})
        before = self.artifact.read_bytes()
        path = record_artifact(self.base / 'receipts', receipt)
        self.assertEqual(self.artifact.read_bytes(), before)
        self.assertNotEqual(path.parent, self.artifact.parent)
        with zipfile.ZipFile(self.artifact) as archive:
            self.assertNotIn('release-2.3.1.json', archive.namelist())

    def test_same_release_different_digest_rejected(self) -> None:
        receipt = artifact_receipt(self.decision, self.artifact, built_from_tree=TREE, toolchain={})
        record_artifact(self.base / 'receipts', receipt)
        record_artifact(self.base / 'receipts', receipt)  # idempotent repeat
        with zipfile.ZipFile(self.artifact, 'a') as archive:
            archive.writestr('extra.txt', 'x')
        other = artifact_receipt(self.decision, self.artifact, built_from_tree=TREE, toolchain={})
        with self.assertRaises(ReleaseStateError):
            record_artifact(self.base / 'receipts', other)

    def test_failed_publish_not_reported_published(self) -> None:
        receipt = artifact_receipt(self.decision, self.artifact, built_from_tree=TREE, toolchain={})
        record_artifact(self.base / 'receipts', receipt)
        self.assertEqual(mark_publication(self.base / 'receipts', '2.3.1', published=False)['publication_status'], 'failed')

    def test_post_publish_state_does_not_rewrite_artifact(self) -> None:
        receipt = artifact_receipt(self.decision, self.artifact, built_from_tree=TREE, toolchain={})
        record_artifact(self.base / 'receipts', receipt)
        before = self.artifact.read_bytes()
        mark_publication(self.base / 'receipts', '2.3.1', published=True, url='https://example.invalid/r')
        self.assertEqual(self.artifact.read_bytes(), before)

    def test_disallowed_decision_builds_no_receipt(self) -> None:
        state = parse_release_state(fixture())
        denied = decide_release(state, source_commit=COMMIT, source_tree=TREE, required_checks=REQUIRED, checks=[],
                                review=None, existing_tags={})
        with self.assertRaises(ReleaseStateError):
            artifact_receipt(denied, self.artifact, built_from_tree=TREE, toolchain={})


if __name__ == '__main__':
    unittest.main()
